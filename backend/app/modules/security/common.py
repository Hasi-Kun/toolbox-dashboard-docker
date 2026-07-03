"""Gemeinsame Helper fuer die Security-Kategorie."""

import httpx

DEFAULT_HEADERS = {"User-Agent": "Toolbox-SecurityScanner/1.0"}


def build_client(timeout: float) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=timeout,
        headers=DEFAULT_HEADERS,
        follow_redirects=True,
        verify=False,  # Wir WOLLEN auch Seiten mit ungueltigen Zertifikaten pruefen koennen
    )
