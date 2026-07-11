"""Parser fuer testssl.sh's flaches JSON-Format (--jsonfile).

Format (ein Array von Einzelbefunden):
  [{"id": "heartbleed", "ip": "1.2.3.4/1.2.3.4", "port": "443",
    "severity": "OK", "cve": "CVE-2014-0160", "finding": "not vulnerable (OK)"}, ...]

severity ist eine von: OK, INFO, LOW, MEDIUM, HIGH, CRITICAL, WARN
(WARN = ein Problem beim Scannen selbst, kein Sicherheitsbefund).
"""

import json


def parse_testssl_json(raw_output: str) -> dict:
    raw_output = raw_output.strip()
    if not raw_output:
        return {"target": None, "findings": [], "vulnerabilities": [], "severity_counts": {}}

    try:
        findings_raw = json.loads(raw_output)
    except json.JSONDecodeError as exc:
        raise ValueError(f"testssl.sh-JSON-Ausgabe konnte nicht geparst werden: {exc}") from exc

    if not isinstance(findings_raw, list):
        raise ValueError("Unerwartetes testssl.sh-Ausgabeformat (kein JSON-Array)")

    findings = []
    vulnerabilities = []
    severity_counts: dict[str, int] = {}
    target_ip = None

    for entry in findings_raw:
        severity = entry.get("severity", "INFO")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        if target_ip is None and entry.get("ip"):
            target_ip = entry["ip"]

        item = {
            "id": entry.get("id"),
            "severity": severity,
            "finding": entry.get("finding"),
            "cve": entry.get("cve"),
            "cwe": entry.get("cwe"),
        }
        findings.append(item)

        # Vulnerability-Eintraege sind die, die ein CVE tragen -- ob sie
        # TATSAECHLICH verwundbar sind, steht in severity (OK = nicht
        # verwundbar, alles andere = ein echter Befund).
        if entry.get("cve"):
            item_copy = dict(item)
            item_copy["vulnerable"] = severity not in ("OK", "INFO", "WARN")
            vulnerabilities.append(item_copy)

    return {
        "target": target_ip,
        "findings": findings,
        "vulnerabilities": vulnerabilities,
        "severity_counts": severity_counts,
    }
