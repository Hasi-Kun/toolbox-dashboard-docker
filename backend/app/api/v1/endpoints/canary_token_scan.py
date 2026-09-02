"""Canary-/Honey-Token-Scanner: sucht in Office-Dokumenten (docx/xlsx/
pptx), ZIP-Archiven und PDFs nach eingebetteten URLs (potenzielle
Tracking-Beacons, die "nach Hause telefonieren", sobald das Dokument
geoeffnet wird) -- rein statische Analyse. Das Dokument wird NIE
tatsaechlich geoeffnet/gerendert und es wird KEINE einzige Netzwerk-
anfrage gestellt -- genau das macht die Erkennung selbst sicher, auch
wenn die Datei tatsaechlich einen Canary-Token enthaelt.

Inspiriert vom Ansatz aus CanaryTokenScanner (0xNslabs):
https://github.com/0xNslabs/CanaryTokenScanner
Eigene Implementierung, angepasst an unsere Endpunkt-/Testinfrastruktur
(z.B. Ziel-Typ-Erkennung ueber Magic Bytes statt allein ueber die
Datei-Endung, damit eine falsch benannte Datei nicht unerkannt bleibt).
"""

import io
import re
import zipfile
import zlib

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel

from app.api.deps import get_current_user
from app.models.user import User

router = APIRouter(prefix="/canary-token-scan", tags=["canary-token-scan"])

MAX_FILE_SIZE_BYTES = 25_000_000  # 25 MB -- Office-Dokumente/PDFs koennen groesser sein als z.B. Zertifikate
MAX_FINDINGS_REPORTED = 200

_URL_RE = re.compile(rb'https?://[^\s"\'<>\)\]]+', re.IGNORECASE)

# Haeufige, harmlose Schema-/Referenz-Domains, die Office-Dokumente
# routinemaessig referenzieren -- rausgefiltert, um Rauschen zu
# vermeiden (sonst waere praktisch JEDES Office-Dokument "verdaechtig").
_IGNORED_DOMAINS = (
    "schemas.openxmlformats.org",
    "schemas.microsoft.com",
    "purl.org",
    "w3.org",
)


class CanaryFinding(BaseModel):
    url: str
    location: str


class CanaryScanResult(BaseModel):
    filename: str
    file_type: str
    suspicious: bool
    findings: list[CanaryFinding]
    findings_truncated: bool


def _clean_url(raw: bytes) -> str:
    text = raw.decode("utf-8", errors="replace")
    # Abschliessende Satzzeichen/Klammern/Anfuehrungszeichen abschneiden,
    # die der Regex haeufig aus dem umgebenden Text mit einfaengt.
    return text.rstrip(".,;:'\")]}")


def _is_ignored(url: str) -> bool:
    return any(domain in url for domain in _IGNORED_DOMAINS)


def _scan_zip_bytes(data: bytes) -> list[CanaryFinding]:
    """Office-Dokumente (docx/xlsx/pptx) sind ZIP-Container -- Member
    werden direkt im Arbeitsspeicher gelesen, nie auf Platte entpackt."""
    findings: list[CanaryFinding] = []
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for name in zf.namelist():
            try:
                member_data = zf.read(name)
            except (zipfile.BadZipFile, RuntimeError, KeyError, NotImplementedError):
                continue
            for match in _URL_RE.finditer(member_data):
                url = _clean_url(match.group())
                if not _is_ignored(url):
                    findings.append(CanaryFinding(url=url, location=name))
    return findings


def _scan_pdf_bytes(data: bytes) -> list[CanaryFinding]:
    findings: list[CanaryFinding] = []

    # 1. Rohe PDF-Bytes direkt durchsuchen -- viele PDFs speichern URLs
    #    unkomprimiert, z.B. in /URI(...)-Eintraegen fuer Links.
    for match in _URL_RE.finditer(data):
        url = _clean_url(match.group())
        if not _is_ignored(url):
            findings.append(CanaryFinding(url=url, location="PDF (unkomprimiert)"))

    # 2. Komprimierte Content-Streams (stream...endstream) einzeln per
    #    Flate/deflate dekomprimieren und ebenfalls durchsuchen -- viele
    #    PDF-Generatoren komprimieren den eigentlichen Seiteninhalt.
    for stream_match in re.finditer(rb"stream\r?\n(.*?)endstream", data, re.DOTALL):
        raw_stream = stream_match.group(1)
        try:
            decompressed = zlib.decompress(raw_stream)
        except zlib.error:
            continue
        for match in _URL_RE.finditer(decompressed):
            url = _clean_url(match.group())
            if not _is_ignored(url):
                findings.append(CanaryFinding(url=url, location="PDF (komprimierter Stream)"))

    return findings


@router.post("", response_model=CanaryScanResult)
async def scan_file(file: UploadFile = File(...), _user: User = Depends(get_current_user)) -> CanaryScanResult:
    content = await file.read(MAX_FILE_SIZE_BYTES + 1)
    if len(content) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(status_code=413, detail=f"Datei zu gross (max. {MAX_FILE_SIZE_BYTES // 1_000_000} MB)")
    if not content:
        raise HTTPException(status_code=422, detail="Datei ist leer")

    # Typ-Erkennung ueber Magic Bytes statt allein ueber die Datei-Endung
    # -- eine falsch benannte oder umbenannte Datei bleibt so trotzdem
    # erkennbar (z.B. eine .zip, die eigentlich eine .docx ist).
    if content.startswith(b"%PDF-"):
        file_type = "pdf"
        findings = _scan_pdf_bytes(content)
    elif zipfile.is_zipfile(io.BytesIO(content)):
        file_type = "office/zip"
        try:
            findings = _scan_zip_bytes(content)
        except zipfile.BadZipFile as exc:
            raise HTTPException(status_code=422, detail=f"ZIP-Datei beschaedigt oder ungueltig: {exc}") from exc
    else:
        raise HTTPException(
            status_code=422,
            detail="Nicht unterstuetztes Format -- erwartet .docx/.xlsx/.pptx/.pdf/.zip (anhand des Dateiinhalts erkannt, nicht der Endung).",
        )

    truncated = len(findings) > MAX_FINDINGS_REPORTED
    findings = findings[:MAX_FINDINGS_REPORTED]

    return CanaryScanResult(
        filename=file.filename or "upload",
        file_type=file_type,
        suspicious=len(findings) > 0,
        findings=findings,
        findings_truncated=truncated,
    )
