"""OpenSSL-Datei-Inspektor: Datei-Upload (PKCS#7/S-MIME, X.509-Zertifikat
oder CSR), read-only Analyse per openssl, Datei wird SOFORT nach der
Analyse geloescht (kein dauerhafter Speicher).

WICHTIG: Der Nutzer waehlt nur einen von drei FESTEN Analyse-Modi -- es
werden niemals frei uebergebene openssl-Kommandozeilenargumente
ausgefuehrt. Das verhindert Command-Injection ueber den Umweg "der Nutzer
darf sich aussuchen, welche openssl-Flags laufen".
"""

import asyncio
import logging
import tempfile
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile

from app.api.deps import get_current_user
from app.models.user import User

logger = logging.getLogger("toolbox.openssl_tool")
router = APIRouter(prefix="/openssl-inspect", tags=["openssl-inspect"])

MAX_FILE_SIZE_BYTES = 1_000_000
MAX_OUTPUT_CHARS = 20_000

_COMMANDS: dict[str, list[list[str]]] = {
    "pkcs7": [
        ["openssl", "pkcs7", "-print_certs", "-text", "-noout", "-in"],
        ["openssl", "pkcs7", "-inform", "DER", "-print_certs", "-text", "-noout", "-in"],
    ],
    "x509": [
        ["openssl", "x509", "-text", "-noout", "-in"],
        ["openssl", "x509", "-inform", "DER", "-text", "-noout", "-in"],
    ],
    "csr": [
        ["openssl", "req", "-text", "-noout", "-in"],
        ["openssl", "req", "-inform", "DER", "-text", "-noout", "-in"],
    ],
}


def _run_openssl_sync(mode: str, file_path: str, timeout: float) -> tuple[bool, str, str]:
    import subprocess

    last_stderr = ""
    for command_template in _COMMANDS[mode]:
        command = [*command_template, file_path]
        try:
            result = subprocess.run(command, capture_output=True, timeout=timeout, text=True)
        except subprocess.TimeoutExpired:
            return False, "", "Zeitueberschreitung bei der openssl-Ausfuehrung"

        if result.returncode == 0 and result.stdout.strip():
            return True, result.stdout[:MAX_OUTPUT_CHARS], ""
        last_stderr = result.stderr

    return False, "", last_stderr[:2000]


@router.post("")
async def inspect_file(
    file: UploadFile = File(...),
    mode: str = Form(...),
    _user: User = Depends(get_current_user),
) -> dict:
    if mode not in _COMMANDS:
        raise HTTPException(status_code=422, detail=f"Ungueltiger Modus, erlaubt: {sorted(_COMMANDS.keys())}")

    content = await file.read(MAX_FILE_SIZE_BYTES + 1)
    if len(content) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(status_code=413, detail=f"Datei zu gross (max. {MAX_FILE_SIZE_BYTES // 1000} KB)")
    if not content:
        raise HTTPException(status_code=422, detail="Datei ist leer")

    tmp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".upload") as tmp_file:
            tmp_file.write(content)
            tmp_path = tmp_file.name

        success, output, error_output = await asyncio.wait_for(
            asyncio.to_thread(_run_openssl_sync, mode, tmp_path, 10.0), timeout=12.0
        )
    except asyncio.TimeoutError:
        return {"success": False, "mode": mode, "output": None, "error": "Zeitueberschreitung"}
    finally:
        if tmp_path is not None:
            try:
                Path(tmp_path).unlink(missing_ok=True)
            except OSError:
                logger.warning("Konnte temporaere Datei nicht loeschen: %s", tmp_path)

    if not success:
        return {
            "success": False, "mode": mode, "output": None,
            "error": f"Konnte Datei nicht als '{mode}' interpretieren (weder PEM noch DER): {error_output}",
        }

    return {"success": True, "mode": mode, "output": output, "error": None}
