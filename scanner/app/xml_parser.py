"""Parst nmap-XML-Output (-oX -) in eine einfache dict-Struktur.

Format verifiziert gegen echte `nmap -oX -`-Ausgaben (siehe Kommentare
in den Tests) -- kein Rätselraten anhand der Doku.
"""

import xml.etree.ElementTree as ET


def parse_nmap_xml(xml_text: str) -> list[dict]:
    root = ET.fromstring(xml_text)
    hosts = []

    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        address_el = host_el.find("address")
        if address_el is None:
            continue

        ports = []
        ports_container = host_el.find("ports")
        if ports_container is not None:
            for port_el in ports_container.findall("port"):
                state_el = port_el.find("state")
                service_el = port_el.find("service")
                ports.append(
                    {
                        "port": int(port_el.get("portid")),
                        "protocol": port_el.get("protocol", "tcp"),
                        "state": state_el.get("state") if state_el is not None else "unknown",
                        "service": service_el.get("name") if service_el is not None else None,
                        "product": service_el.get("product") if service_el is not None else None,
                        "version": service_el.get("version") if service_el is not None else None,
                    }
                )

        os_guesses = []
        os_container = host_el.find("os")
        if os_container is not None:
            for match_el in os_container.findall("osmatch"):
                name = match_el.get("name")
                accuracy = match_el.get("accuracy")
                if name:
                    os_guesses.append(f"{name} ({accuracy}%)" if accuracy else name)

        hosts.append(
            {
                "address": address_el.get("addr", "unknown"),
                "status": status_el.get("state") if status_el is not None else "unknown",
                "ports": ports,
                "os_guesses": os_guesses,
            }
        )

    return hosts
