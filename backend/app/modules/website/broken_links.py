import asyncio
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import httpx
from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname, is_valid_ip

MAX_LINKS = 30


class _LinkExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "a":
            for name, value in attrs:
                if name == "href" and value:
                    self.links.append(value)


class LinkCheckResult(BaseModel):
    url: str
    status_code: int | None
    ok: bool
    error: str | None = None


@register_module
class BrokenLinksModule(ToolModule):
    slug = "broken-links-checker"
    category = "website"
    name = "Broken Links Checker"
    description = f"Prueft die ersten {MAX_LINKS} Links einer Seite auf tote Links (4xx/5xx/Fehler)."
    is_active_scan = False
    timeout_seconds = 30

    class Input(BaseModel):
        domain: str

        @field_validator("domain")
        @classmethod
        def validate_domain(cls, v: str) -> str:
            v = v.strip().rstrip("/")
            for prefix in ("https://", "http://"):
                if v.startswith(prefix):
                    v = v[len(prefix):]
            v = v.split("/")[0]
            if not (is_valid_hostname(v) or is_valid_ip(v)):
                raise ValueError("Ungueltige Domain")
            return v

    class Output(BaseModel):
        domain: str
        success: bool
        checked_count: int = 0
        broken_count: int = 0
        results: list[LinkCheckResult] = []
        error: str | None = None

    async def run(self, data: Input) -> Output:
        base_url = f"https://{data.domain}/"
        try:
            async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False) as client:
                page_response = await client.get(base_url, headers={"User-Agent": "Toolbox-LinkCheck/1.0"})
        except httpx.HTTPError as exc:
            return self.Output(domain=data.domain, success=False, error=str(exc))

        parser = _LinkExtractor()
        parser.feed(page_response.text[:500_000])

        seen: set[str] = set()
        absolute_links: list[str] = []
        for href in parser.links:
            if href.startswith(("mailto:", "tel:", "javascript:", "#")):
                continue
            absolute = urljoin(str(page_response.url), href)
            if urlparse(absolute).scheme not in ("http", "https"):
                continue
            if absolute not in seen:
                seen.add(absolute)
                absolute_links.append(absolute)
            if len(absolute_links) >= MAX_LINKS:
                break

        results = await asyncio.gather(*(self._check_link(url) for url in absolute_links))
        broken_count = sum(1 for r in results if not r.ok)

        return self.Output(
            domain=data.domain, success=True, checked_count=len(results),
            broken_count=broken_count, results=results, error=None,
        )

    @staticmethod
    async def _check_link(url: str) -> LinkCheckResult:
        try:
            async with httpx.AsyncClient(timeout=8, follow_redirects=True, verify=False) as client:
                response = await client.head(url, headers={"User-Agent": "Toolbox-LinkCheck/1.0"})
                if response.status_code >= 400:
                    # manche Server unterstuetzen HEAD schlecht -- GET als Fallback
                    response = await client.get(url, headers={"User-Agent": "Toolbox-LinkCheck/1.0"})
            return LinkCheckResult(url=url, status_code=response.status_code, ok=response.status_code < 400)
        except httpx.HTTPError as exc:
            return LinkCheckResult(url=url, status_code=None, ok=False, error=str(exc))
