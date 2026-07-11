"""Prueft, ob extern eingebundene <script>- und <link>-Tags einer Seite
Subresource-Integrity-Hashes (integrity="...") verwenden -- ohne SRI
kann eine kompromittierte CDN/Drittanbieter-Ressource unbemerkt
schaedlichen Code nachladen.
"""

import re
import urllib.parse

import httpx
from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname, is_valid_ip

_SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>', re.IGNORECASE)
_LINK_STYLESHEET_RE = re.compile(r'<link[^>]+rel=["\']stylesheet["\'][^>]*>', re.IGNORECASE)
_HREF_RE = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
_INTEGRITY_RE = re.compile(r'integrity=["\']([^"\']+)["\']', re.IGNORECASE)


class ExternalResource(BaseModel):
    url: str
    tag_type: str  # "script" | "stylesheet"
    has_integrity: bool


@register_module
class SriCheckerModule(ToolModule):
    slug = "sri-checker"
    category = "security"
    name = "Subresource-Integrity-Checker"
    description = (
        "Prueft, ob extern eingebundene <script>- und <link>-Tags einer Seite Subresource-Integrity-"
        "Hashes (integrity=\"...\") nutzen -- ohne SRI kann eine kompromittierte CDN-/Drittanbieter-"
        "Ressource unbemerkt schaedlichen Code nachladen."
    )
    is_active_scan = False
    timeout_seconds = 12

    class Input(BaseModel):
        url: str

        @field_validator("url")
        @classmethod
        def validate_url(cls, v: str) -> str:
            v = v.strip()
            if not v.startswith(("http://", "https://")):
                v = f"https://{v}"
            host = v.split("://", 1)[1].split("/")[0]
            if not (is_valid_hostname(host) or is_valid_ip(host)):
                raise ValueError("Ungueltige URL")
            return v

    class Output(BaseModel):
        url: str
        success: bool
        external_resources: list[ExternalResource] = []
        missing_integrity_count: int = 0
        error: str | None = None

    async def run(self, data: Input) -> Output:
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds, follow_redirects=True) as client:
                response = await client.get(data.url, headers={"User-Agent": "Toolbox-SRI-Checker/1.0"})
        except httpx.HTTPError as exc:
            return self.Output(url=data.url, success=False, error=str(exc))

        page_host = urllib.parse.urlsplit(str(response.url)).netloc
        html = response.text[:2_000_000]  # Sicherheitsgrenze gegen extrem grosse Seiten
        resources: list[ExternalResource] = []

        for match in _SCRIPT_SRC_RE.finditer(html):
            full_tag = match.group(0)
            src = match.group(1)
            if not _is_external(src, page_host):
                continue
            has_integrity = bool(_INTEGRITY_RE.search(full_tag))
            resources.append(ExternalResource(url=src, tag_type="script", has_integrity=has_integrity))

        for match in _LINK_STYLESHEET_RE.finditer(html):
            full_tag = match.group(0)
            href_match = _HREF_RE.search(full_tag)
            if not href_match:
                continue
            href = href_match.group(1)
            if not _is_external(href, page_host):
                continue
            has_integrity = bool(_INTEGRITY_RE.search(full_tag))
            resources.append(ExternalResource(url=href, tag_type="stylesheet", has_integrity=has_integrity))

        missing = sum(1 for r in resources if not r.has_integrity)
        return self.Output(url=data.url, success=True, external_resources=resources, missing_integrity_count=missing)


def _is_external(src: str, page_host: str) -> bool:
    if src.startswith("//"):
        host = src[2:].split("/")[0]
        return host != page_host
    if src.startswith("http://") or src.startswith("https://"):
        host = urllib.parse.urlsplit(src).netloc
        return host != page_host
    return False  # relativer Pfad -- gleiche Origin, kein SRI-relevantes Drittanbieter-Risiko
