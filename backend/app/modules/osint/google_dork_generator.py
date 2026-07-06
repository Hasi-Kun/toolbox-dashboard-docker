from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname


@register_module
class GoogleDorkGeneratorModule(ToolModule):
    slug = "google-dork-generator"
    category = "osint"
    name = "Google Dork Generator"
    description = (
        "Erzeugt nuetzliche Google-Dork-Suchanfragen fuer eine Domain (site:, filetype:, inurl: etc) "
        "als Ausgangspunkt fuer passive Recherche. Rein lokale Textgenerierung, keine externe API, "
        "fuehrt selbst keine Suche aus."
    )
    is_active_scan = False
    timeout_seconds = 3

    class Input(BaseModel):
        domain: str

        @field_validator("domain")
        @classmethod
        def validate_domain(cls, v: str) -> str:
            v = v.strip().rstrip(".")
            if not is_valid_hostname(v):
                raise ValueError("Ungueltige Domain")
            return v

    class Dork(BaseModel):
        query: str
        purpose: str

    class Output(BaseModel):
        domain: str
        dorks: list["GoogleDorkGeneratorModule.Dork"]

    async def run(self, data: Input) -> Output:
        d = data.domain
        dorks = [
            self.Dork(query=f"site:{d}", purpose="Alle indexierten Seiten der Domain"),
            self.Dork(query=f"site:{d} filetype:pdf", purpose="Oeffentliche PDF-Dokumente"),
            self.Dork(query=f"site:{d} filetype:xlsx OR filetype:csv", purpose="Oeffentliche Tabellen/Exporte"),
            self.Dork(query=f"site:{d} inurl:login", purpose="Login-Seiten"),
            self.Dork(query=f"site:{d} inurl:admin", purpose="Admin-Bereiche"),
            self.Dork(query=f"site:{d} inurl:wp-content OR inurl:wp-admin", purpose="WordPress-Installationen"),
            self.Dork(query=f'site:{d} "index of /"', purpose="Offene Verzeichnislisten"),
            self.Dork(query=f"site:{d} ext:sql OR ext:log OR ext:bak", purpose="Versehentlich veroeffentlichte Backups/Logs"),
            self.Dork(query=f'site:{d} intitle:"confidential" OR intitle:"internal"', purpose="Als vertraulich markierte Seiten"),
            self.Dork(query=f'site:pastebin.com "{d}"', purpose="Erwaehnungen auf Pastebin (z.B. geleakte Configs)"),
            self.Dork(query=f'site:github.com "{d}"', purpose="Erwaehnungen in oeffentlichen GitHub-Repos"),
            self.Dork(query=f'-site:{d} "{d}"', purpose="Erwaehnungen der Domain auf ANDEREN Seiten"),
        ]
        return self.Output(domain=d, dorks=dorks)
