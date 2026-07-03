from html.parser import HTMLParser

import httpx
from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname, is_valid_ip


class _MetaTagParser(HTMLParser):
    """Minimaler HTML-Parser nur fuer die paar Tags, die uns interessieren --
    bewusst stdlib statt einer HTML-Parsing-Bibliothek wie BeautifulSoup,
    das waere fuer diesen begrenzten Zweck ueberdimensioniert.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title: str | None = None
        self.description: str | None = None
        self.canonical: str | None = None
        self.robots: str | None = None
        self.viewport: str | None = None
        self.og_title: str | None = None
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_dict = {k.lower(): (v or "") for k, v in attrs}

        if tag == "title":
            self._in_title = True
        elif tag == "meta":
            name = attr_dict.get("name", "").lower()
            prop = attr_dict.get("property", "").lower()
            content = attr_dict.get("content")
            if name == "description":
                self.description = content
            elif name == "robots":
                self.robots = content
            elif name == "viewport":
                self.viewport = content
            elif prop == "og:title":
                self.og_title = content
        elif tag == "link" and attr_dict.get("rel", "").lower() == "canonical":
            self.canonical = attr_dict.get("href")

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title = (self.title or "") + data


@register_module
class MetaTagsModule(ToolModule):
    slug = "meta-tags"
    category = "website"
    name = "Meta Tags Check"
    description = "Prueft Title, Meta-Description, Canonical, Robots-Meta und Viewport einer Seite (Basis-SEO)."
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
        success: bool
        title: str | None = None
        title_length: int | None = None
        description: str | None = None
        description_length: int | None = None
        canonical: str | None = None
        robots: str | None = None
        viewport: str | None = None
        og_title: str | None = None
        warnings: list[str] = []
        error: str | None = None

    async def run(self, data: Input) -> Output:
        url = f"https://{data.domain}/"
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds, follow_redirects=True, verify=False) as client:
                response = await client.get(url, headers={"User-Agent": "Toolbox-MetaCheck/1.0"})
        except httpx.HTTPError as exc:
            return self.Output(domain=data.domain, success=False, error=str(exc))

        parser = _MetaTagParser()
        parser.feed(response.text[:200_000])  # genug fuer den <head>-Bereich, kein Grund den ganzen Body zu parsen

        title = parser.title.strip() if parser.title else None
        description = parser.description.strip() if parser.description else None

        warnings: list[str] = []
        if not title:
            warnings.append("Kein <title>-Tag gefunden.")
        elif len(title) > 60:
            warnings.append(f"Title ist {len(title)} Zeichen lang -- in Suchergebnissen wird meist bei ~60 abgeschnitten.")
        if not description:
            warnings.append("Keine Meta-Description gefunden.")
        elif len(description) > 160:
            warnings.append(f"Meta-Description ist {len(description)} Zeichen lang -- meist wird bei ~160 abgeschnitten.")
        if parser.robots and "noindex" in parser.robots.lower():
            warnings.append("robots-Meta enthaelt 'noindex' -- Seite wird von Suchmaschinen ausgeschlossen.")
        if not parser.viewport:
            warnings.append("Kein viewport-Meta-Tag -- kann auf mobilen Geraeten zu Darstellungsproblemen fuehren.")

        return self.Output(
            domain=data.domain, success=True, title=title,
            title_length=len(title) if title else None,
            description=description,
            description_length=len(description) if description else None,
            canonical=parser.canonical, robots=parser.robots, viewport=parser.viewport,
            og_title=parser.og_title, warnings=warnings, error=None,
        )
