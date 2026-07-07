"""Parser fuer Niktos JSON-Ausgabe (-Format json).

WICHTIG: Basiert auf der oeffentlich dokumentierten Nikto-JSON-Struktur,
konnte aber in dieser Entwicklungsumgebung NICHT gegen einen echten
Nikto-Lauf verifiziert werden (kein Netzwerkzugriff fuer einen echten
Scan hier). Bewusst defensiv geschrieben (ueberall .get() mit
Fallbacks), damit kleinere Strukturabweichungen zwischen Nikto-Versionen
nicht zu einem Absturz fuehren, sondern hoechstens zu fehlenden
Detailfeldern. Nach dem ersten echten Einsatz ggf. nachjustieren.
"""

import json


def parse_nikto_json(raw_output: str) -> dict:
    raw_output = raw_output.strip()
    if not raw_output:
        return {"host": None, "ip": None, "port": None, "findings": []}

    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError:
        start = raw_output.find("{")
        end = raw_output.rfind("}")
        if start == -1 or end == -1 or end <= start:
            raise ValueError("Nikto-Ausgabe enthielt kein erkennbares JSON")
        data = json.loads(raw_output[start : end + 1])

    vulnerabilities = data.get("vulnerabilities", [])
    findings = [
        {
            "id": v.get("id"),
            "method": v.get("method"),
            "url": v.get("url"),
            "message": v.get("msg") or v.get("message"),
            "references": v.get("references"),
        }
        for v in vulnerabilities
    ]

    return {
        "host": data.get("host"),
        "ip": data.get("ip"),
        "port": data.get("port"),
        "banner": data.get("banner"),
        "findings": findings,
        "finding_count": len(findings),
    }
