"""Parser fuer Niktos XML-Ausgabe (-Format xml).

WARUM XML STATT JSON: Nach drei erfolglosen Anlaeufen, die JSON-Ausgabe
zum Laufen zu bringen (fehlendes Perl-Modul vermutet, dann behoben, dann
GENAU DERSELBE Laufzeitfehler trotzdem wieder aufgetreten -- vermutlich
ein Bug in Niktos eigenem JSON-Report-Plugin in Version 2.5.0, siehe
https://github.com/sullo/nikto/issues/793: "nikto-2.5.0 start failed...
if i switch to 2.1.6, it can succeed"), wird jetzt auf XML umgestellt.
XML ist Niktos laenger etablierter, ausgereifterer Ausgabepfad (seit
Version 2.02, Baujahr 2008) und haengt nicht vom soeben Aerger machenden
JSON-Modul ab.

Bekannte Eigenart neuerer Nikto-Versionen (siehe GitHub-Issue #670):
das <niktoscan>-Wurzelelement kann DOPPELT verschachtelt sein
(<niktoscan><niktoscan>...</niktoscan></niktoscan>). Der Parser sucht
deshalb bewusst mit .iter() nach <scandetails>/<item> UNABHAENGIG von der
Verschachtelungstiefe, statt eine feste Struktur anzunehmen.
"""

import xml.etree.ElementTree as ET


def parse_nikto_xml(raw_output: str) -> dict:
    raw_output = raw_output.strip()
    if not raw_output:
        return {"host": None, "ip": None, "port": None, "findings": []}

    # DOCTYPE-Zeile referenziert eine lokale DTD-Datei -- Python's
    # ElementTree versucht diese NICHT aufzuloesen (kein externer
    # Netzwerk-/Datei-Zugriff durch das Parsen selbst), aber zur
    # Sicherheit trotzdem entfernen, falls eine XML-Parser-Konfiguration
    # das jemals anders handhaben wuerde.
    if "<!DOCTYPE" in raw_output:
        start = raw_output.find("<!DOCTYPE")
        end = raw_output.find(">", start)
        if start != -1 and end != -1:
            raw_output = raw_output[:start] + raw_output[end + 1 :]

    try:
        root = ET.fromstring(raw_output)
    except ET.ParseError as exc:
        raise ValueError(f"Nikto-XML-Ausgabe konnte nicht geparst werden: {exc}") from exc

    scandetails = root.find(".//scandetails")
    if scandetails is None:
        return {"host": None, "ip": None, "port": None, "findings": []}

    findings = []
    for item in scandetails.iter("item"):
        description_el = item.find("description")
        uri_el = item.find("uri")
        findings.append({
            "id": item.get("id"),
            "method": item.get("method"),
            "url": uri_el.text if uri_el is not None else None,
            "message": description_el.text if description_el is not None else None,
            "references": item.get("osvdblink"),
        })

    return {
        "host": scandetails.get("targethostname"),
        "ip": scandetails.get("targetip"),
        "port": scandetails.get("targetport"),
        "banner": scandetails.get("targetbanner"),
        "findings": findings,
        "finding_count": len(findings),
    }
