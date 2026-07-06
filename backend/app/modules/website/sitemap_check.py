import xml.etree.ElementTree as ET

import httpx
from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname, is_valid_ip

_SITEMAP_NS = "{http://www.sitemaps.org/schemas/sitemap/0.9}"


@register_module
class SitemapCheckModule(ToolModule):
    slug = "sitemap-check"
    category = "website"
    name = "Sitemap Check"
    description = "Prueft sitemap.xml auf Erreichbarkeit, gueltiges XML und listet enthaltene URLs/Sitemaps."
    is_active_scan = False
    timeout_seconds = 12

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
        found: bool
        is_sitemap_index: bool = False
        url_count: int = 0
        sample_urls: list[str] = []
        checked_in_robots_txt: bool = False
        warnings: list[str] = []
        error: str | None = None

    async def run(self, data: Input) -> Output:
        checked_in_robots = False

        async with httpx.AsyncClient(timeout=self.timeout_seconds, follow_redirects=True, verify=False) as client:
            # 1. robots.txt nach einem Sitemap-Verweis durchsuchen (haeufigster,
            #    korrekter Ort fuer die Sitemap-URL)
            sitemap_url = f"https://{data.domain}/sitemap.xml"
            try:
                robots_response = await client.get(f"https://{data.domain}/robots.txt")
                if robots_response.status_code == 200:
                    for line in robots_response.text.splitlines():
                        if line.strip().lower().startswith("sitemap:"):
                            sitemap_url = line.split(":", 1)[1].strip()
                            checked_in_robots = True
                            break
            except httpx.HTTPError:
                pass

            try:
                response = await client.get(sitemap_url, headers={"User-Agent": "Toolbox-SitemapCheck/1.0"})
            except httpx.HTTPError as exc:
                return self.Output(domain=data.domain, found=False, checked_in_robots_txt=checked_in_robots, error=str(exc))

        if response.status_code != 200:
            return self.Output(
                domain=data.domain, found=False, checked_in_robots_txt=checked_in_robots,
                warnings=[f"Sitemap nicht erreichbar unter {sitemap_url} (HTTP {response.status_code})"],
            )

        try:
            root = ET.fromstring(response.content)
        except ET.ParseError as exc:
            return self.Output(
                domain=data.domain, found=True, checked_in_robots_txt=checked_in_robots,
                warnings=[f"Sitemap gefunden, aber kein gueltiges XML: {exc}"],
            )

        is_index = root.tag == f"{_SITEMAP_NS}sitemapindex"
        tag_name = "sitemap" if is_index else "url"
        entries = root.findall(f"{_SITEMAP_NS}{tag_name}")
        urls = [
            loc.text.strip()
            for entry in entries
            if (loc := entry.find(f"{_SITEMAP_NS}loc")) is not None and loc.text
        ]

        warnings: list[str] = []
        if not urls:
            warnings.append("Sitemap ist leer oder folgt nicht dem Standard-Schema.")

        return self.Output(
            domain=data.domain, found=True, is_sitemap_index=is_index,
            url_count=len(urls), sample_urls=urls[:10],
            checked_in_robots_txt=checked_in_robots, warnings=warnings, error=None,
        )
