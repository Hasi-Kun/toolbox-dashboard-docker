"""Gemeinsamer Subprocess-Helper fuer Netzwerk-Tools (ping, traceroute, whois).

Bewusst zentral: IMMER `create_subprocess_exec` mit einer Argument-Liste,
NIE `shell=True` oder String-Konkatenation. Damit ist Command-Injection
strukturell ausgeschlossen, nicht nur durch Input-Validierung verhindert --
selbst wenn ein Validator irgendwo eine Luecke haette, gibt es keine Shell,
die Metazeichen interpretieren koennte.
"""

from __future__ import annotations

import asyncio


async def run_subprocess(args: list[str], timeout: float) -> dict:
    """Fuehrt einen Subprozess aus argv-Liste aus, mit hartem Timeout.

    Gibt immer ein dict zurueck (nie eine Exception fuer Timeouts/Fehler),
    damit aufrufende Module den Fehlerfall ohne try/except-Ketten behandeln.
    """
    try:
        process = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        return {"success": False, "stdout": "", "stderr": "", "returncode": None, "error": f"Programm nicht gefunden: {args[0]}"}

    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        return {"success": False, "stdout": "", "stderr": "", "returncode": None, "error": "Zeitueberschreitung"}

    return {
        "success": process.returncode == 0,
        "stdout": stdout_bytes.decode("utf-8", errors="replace"),
        "stderr": stderr_bytes.decode("utf-8", errors="replace"),
        "returncode": process.returncode,
        "error": None,
    }
