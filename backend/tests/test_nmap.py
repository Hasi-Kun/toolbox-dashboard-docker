"""Tests fuer die Nmap-Modul-Validierung. Der komplette End-to-End-Flow
(Backend-Modul -> Redis-Queue -> Scanner-Worker -> echter nmap-Scan) wurde
manuell ueber zwei echte Prozesse + echten Redis verifiziert (siehe
Kommentare in scan_queue.py / scanner/app/worker.py) -- hier wird die
synchron pruefbare Validierungslogik abgedeckt.
"""

import pytest
from pydantic import ValidationError

from app.modules.nmap.quick import NmapQuickScanModule
from app.modules.nmap.service_detection import MAX_PORTS, NmapServiceDetectionModule
from app.modules.nmap.top_ports import NmapTopPortsModule
from app.modules.nmap.udp import MAX_UDP_PORTS, NmapUdpScanModule


def test_quick_scan_rejects_invalid_target():
    with pytest.raises(ValidationError):
        NmapQuickScanModule.Input(target="127.0.0.1; rm -rf /")


def test_top_ports_count_is_clamped():
    assert NmapTopPortsModule.Input(target="example.com", count=0).count == 1
    assert NmapTopPortsModule.Input(target="example.com", count=5000).count == 1000
    assert NmapTopPortsModule.Input(target="example.com", count=250).count == 250


def test_udp_scan_count_is_clamped_lower_than_tcp():
    assert NmapUdpScanModule.Input(target="example.com", count=1000).count == MAX_UDP_PORTS


def test_service_detection_rejects_too_many_ports():
    with pytest.raises(ValidationError):
        NmapServiceDetectionModule.Input(target="example.com", ports=list(range(1, MAX_PORTS + 5)))


def test_service_detection_rejects_out_of_range_port():
    with pytest.raises(ValidationError):
        NmapServiceDetectionModule.Input(target="example.com", ports=[70000])


def test_service_detection_requires_at_least_one_port():
    with pytest.raises(ValidationError):
        NmapServiceDetectionModule.Input(target="example.com", ports=[])


def test_all_nmap_modules_are_marked_as_active_scan():
    from app.modules import get_registry

    registry = get_registry()
    nmap_modules = {slug: cls for slug, cls in registry.items() if cls.category == "nmap"}
    assert len(nmap_modules) == 7
    assert all(cls.is_active_scan for cls in nmap_modules.values())
