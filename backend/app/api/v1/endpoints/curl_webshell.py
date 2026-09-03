"""Curl-Webshell: fuehrt vom Nutzer selbst geschriebene curl-Befehle
tatsaechlich aus (echter curl-Binary, kein httpx-Nachbau) -- Ergaenzung
zum GUI-basierten Curl Browser Tool fuer den Fall, dass man einen
komplexeren, selbst gebauten Befehl direkt testen will.

SICHERHEITSMODELL (wichtig, bewusst restriktiv):
- ALLOWLIST statt Blacklist fuer Flags: nur explizit erlaubte curl-
  Optionen sind zulaessig, alles andere wird abgelehnt. Eine Blacklist
  ("verbiete diese gefaehrlichen Flags") waere strukturell unvollstaendig
  -- curl hat sehr viele Optionen, und neue/vergessene waeren ein Leck.
- Kein Shell-Aufruf (`shell=True`): der Befehl wird mit `shlex.split()`
  in einzelne Argumente zerlegt und DIREKT an subprocess uebergeben --
  Shell-Metazeichen (`;`, `|`, `` ` ``, `$()`, `>`) werden dadurch NIE
  als Shell-Syntax interpretiert, sondern hoechstens als (meist
  ungueltiger) Teil eines curl-Arguments. Das eliminiert die klassische
  Command-Injection-Klasse strukturell, nicht nur per Blacklist.
- Nur http/https als Ziel-Schema erlaubt (kein file://, kein gopher://
  fuer SSRF-artige Protokoll-Spielereien).
- Argumente mit "@"-Praefix (curls Syntax fuer "lies den Wert aus einer
  lokalen Datei", z.B. bei -d/-F/-K/--cacert) werden pauschal
  abgelehnt -- verhindert, dass der Container-eigene Dateisystem-Inhalt
  ausgelesen und im Response an ein beliebiges Ziel gesendet wird.
- Timeout + Output-Groessenbegrenzung, laeuft als derselbe nicht-root
  appuser wie der Rest des Backends (kein --privileged, keine
  zusaetzlichen Capabilities).
- Admin-only, jede Ausfuehrung wird im Audit-Log festgehalten.
"""

import asyncio
import shlex

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from app.api.deps import require_admin
from app.core.audit import get_client_ip, log_audit_event
from app.core.db import get_db
from app.models.user import User

router = APIRouter(prefix="/curl-webshell", tags=["curl-webshell"])

MAX_COMMAND_CHARS = 4000
MAX_OUTPUT_CHARS = 200_000
TIMEOUT_SECONDS = 20

# Bewusst nur die gaengigsten, ungefaehrlichen Optionen fuer "HTTP-
# Anfrage bauen und Antwort ansehen" -- alles, was lokale Dateien liest/
# schreibt oder die Anfrage-Ausfuehrung selbst manipuliert (Config-Datei,
# Zertifikate, Uploads), ist bewusst NICHT enthalten.
ALLOWED_FLAGS = {
    "-X", "--request",
    "-H", "--header",
    "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode",
    "-G", "--get",
    "-I", "--head",
    "-L", "--location",
    "-k", "--insecure",
    "-A", "--user-agent",
    "-e", "--referer",
    "-b", "--cookie",
    "-u", "--user",
    "--compressed",
    "-s", "--silent",
    "-S", "--show-error",
    "-i", "--include",
    "-m", "--max-time",
    "--http1.1", "--http2",
    "-4", "--ipv4",
    "-6", "--ipv6",
    "-w", "--write-out",
}

# Flags, die einen Wert im NAECHSTEN Argument erwarten (fuer die
# @-Datei-Praefix-Pruefung muss bekannt sein, welches Argument der
# "Wert" eines Flags ist statt selbst ein Flag/URL).
FLAGS_WITH_VALUE = {
    "-X", "--request", "-H", "--header", "-d", "--data", "--data-raw",
    "--data-binary", "--data-urlencode", "-A", "--user-agent", "-e",
    "--referer", "-b", "--cookie", "-u", "--user", "-m", "--max-time", "-w", "--write-out",
}


class CurlWebshellRequest(BaseModel):
    command: str

    @field_validator("command")
    @classmethod
    def validate_command(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Befehl darf nicht leer sein")
        if len(v) > MAX_COMMAND_CHARS:
            raise ValueError(f"Befehl zu lang (max. {MAX_COMMAND_CHARS} Zeichen)")
        return v


class CurlWebshellResponse(BaseModel):
    exit_code: int
    output: str
    output_truncated: bool
    error: str | None = None


def _validate_and_parse(command: str) -> list[str]:
    try:
        tokens = shlex.split(command)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Befehl konnte nicht geparst werden (z.B. nicht geschlossenes Anfuehrungszeichen): {exc}") from exc

    if not tokens or tokens[0] != "curl":
        raise HTTPException(status_code=422, detail="Befehl muss mit 'curl' beginnen.")

    expecting_value_for: str | None = None
    saw_url = False

    for token in tokens[1:]:
        if expecting_value_for is not None:
            if token.startswith("@"):
                raise HTTPException(status_code=403, detail=f"'@'-Dateiverweise sind nicht erlaubt (bei {expecting_value_for}).")
            expecting_value_for = None
            continue

        if token.startswith("-"):
            # "--header=Wert"/"-Hwert"-Kurzschreibweisen abfangen: den
            # Flag-Namen bis zum ersten "=" pruefen, den Rest als Wert
            # behandeln (auf @ pruefen).
            flag_part = token.split("=", 1)[0]
            if flag_part not in ALLOWED_FLAGS:
                raise HTTPException(status_code=403, detail=f"Option '{flag_part}' ist nicht erlaubt. Erlaubt sind nur grundlegende HTTP-Anfrage-Optionen.")
            if "=" in token and token.split("=", 1)[1].startswith("@"):
                raise HTTPException(status_code=403, detail=f"'@'-Dateiverweise sind nicht erlaubt (bei {flag_part}).")
            if flag_part in FLAGS_WITH_VALUE and "=" not in token:
                expecting_value_for = flag_part
            continue

        # Kein Flag -- das ist die Ziel-URL (curl erlaubt auch mehrere,
        # wir beschraenken bewusst auf eine, um die Pruefung einfach und
        # nachvollziehbar zu halten).
        if saw_url:
            raise HTTPException(status_code=422, detail="Nur eine Ziel-URL pro Befehl erlaubt.")
        if token.startswith("@"):
            raise HTTPException(status_code=403, detail="'@'-Dateiverweise sind nicht erlaubt.")
        if not (token.startswith("http://") or token.startswith("https://")):
            raise HTTPException(status_code=403, detail="Nur http:// oder https:// als Ziel erlaubt (z.B. kein file://).")
        saw_url = True

    if expecting_value_for is not None:
        raise HTTPException(status_code=422, detail=f"Option '{expecting_value_for}' erwartet einen Wert.")
    if not saw_url:
        raise HTTPException(status_code=422, detail="Keine Ziel-URL im Befehl gefunden.")

    return tokens


@router.post("", response_model=CurlWebshellResponse)
async def run_curl_command(
    payload: CurlWebshellRequest, request: Request, db: Session = Depends(get_db), admin: User = Depends(require_admin)
) -> CurlWebshellResponse:
    tokens = _validate_and_parse(payload.command)

    try:
        process = await asyncio.create_subprocess_exec(
            *tokens,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=TIMEOUT_SECONDS)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            log_audit_event(db, "curl_webshell_run", success=False, username=admin.username, ip_address=get_client_ip(request), detail=f"{payload.command[:200]} (Zeitueberschreitung)")
            return CurlWebshellResponse(exit_code=-1, output="", output_truncated=False, error=f"Zeitueberschreitung nach {TIMEOUT_SECONDS}s")
    except FileNotFoundError as exc:
        raise HTTPException(status_code=500, detail="curl ist im Backend-Container nicht installiert.") from exc

    output = (stdout + stderr).decode("utf-8", errors="replace")
    truncated = len(output) > MAX_OUTPUT_CHARS
    if truncated:
        output = output[:MAX_OUTPUT_CHARS]

    log_audit_event(db, "curl_webshell_run", success=process.returncode == 0, username=admin.username, ip_address=get_client_ip(request), detail=payload.command[:200])

    return CurlWebshellResponse(exit_code=process.returncode, output=output, output_truncated=truncated, error=None)
