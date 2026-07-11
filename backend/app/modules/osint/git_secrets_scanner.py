"""Sucht ueber die GitHub Code-Search-API nach oeffentlichen Repos, die
den eigenen Domain-/Firmennamen zusammen mit typischen Secret-
Dateitypen erwaehnen (z.B. versehentlich committete .env-Dateien).

WICHTIG: Zeigt bewusst NUR Fundstellen (Repo, Dateipfad, Link) an, NIE
den tatsaechlichen Dateiinhalt -- das Tool soll auf moegliche Lecks
hinweisen, nicht selbst zu einer Stelle werden, an der echte Secrets
angezeigt werden. Erfordert einen vom Nutzer selbst bereitgestellten
GitHub-Token (wird nie gespeichert/geloggt) fuer ausreichende
Rate-Limits -- ohne Token ist die GitHub-Code-Search-API praktisch
unbenutzbar (sehr enges anonymes Rate-Limit).
"""

import asyncio

import httpx
from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module

# Dateiendungen/-namen, die haeufig versehentlich committete Secrets
# enthalten -- bewusst eine kleine, dokumentierte Liste statt einer
# erschoepfenden Aufzaehlung.
_SECRET_PRONE_EXTENSIONS = ["env", "pem", "yml", "yaml", "json", "config", "ini"]


class GitSecretMatch(BaseModel):
    repository: str
    path: str
    url: str


@register_module
class GitSecretsScannerModule(ToolModule):
    slug = "git-secrets-scanner"
    category = "osint"
    name = "Git-Secrets-Scanner"
    description = (
        "Sucht ueber die GitHub Code-Search-API nach oeffentlichen Repos, die den eigenen Domain-/"
        "Firmennamen zusammen mit typischen Secret-Dateitypen erwaehnen (z.B. versehentlich "
        "committete .env-Dateien). Zeigt nur Fundstellen (Repo/Pfad/Link), nie den Dateiinhalt. "
        "Erfordert einen eigenen GitHub-Token (wird nicht gespeichert)."
    )
    is_active_scan = False
    timeout_seconds = 20
    redact_input_in_history = True  # der GitHub-Token darf nie in der Historie landen

    class Input(BaseModel):
        query: str
        github_token: str

        @field_validator("query")
        @classmethod
        def validate_query(cls, v: str) -> str:
            v = v.strip()
            if not v or len(v) > 100:
                raise ValueError("Suchbegriff muss 1-100 Zeichen haben")
            return v

        @field_validator("github_token")
        @classmethod
        def validate_token(cls, v: str) -> str:
            if not v.strip():
                raise ValueError("GitHub-Token erforderlich (ohne Token ist die Code-Search-API praktisch unbenutzbar)")
            return v.strip()

    class Output(BaseModel):
        query: str
        success: bool
        total_matches_reported_by_github: int = 0
        matches: list[GitSecretMatch] = []
        error: str | None = None

    async def run(self, data: Input) -> Output:
        # Kombiniert den Suchbegriff mit typischen Secret-Dateiendungen --
        # GitHub-Code-Search-Syntax: mehrere "extension:"-Qualifier lassen
        # sich nicht per OR kombinieren, daher mehrere Anfragen parallel.
        headers = {
            "Authorization": f"Bearer {data.github_token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "Toolbox-Git-Secrets-Scanner/1.0",
        }

        async def search_extension(client: httpx.AsyncClient, ext: str) -> tuple[list[dict], int, str | None]:
            params = {"q": f'"{data.query}" extension:{ext}', "per_page": 5}
            try:
                response = await client.get("https://api.github.com/search/code", params=params, headers=headers)
            except httpx.HTTPError as exc:
                return [], 0, str(exc)
            if response.status_code == 401:
                return [], 0, "GitHub-Token ungueltig oder abgelaufen"
            if response.status_code == 403:
                return [], 0, "Rate-Limit erreicht oder Token ohne noetige Berechtigung"
            if response.status_code != 200:
                return [], 0, f"GitHub antwortete mit HTTP {response.status_code}"
            body = response.json()
            return body.get("items", []), body.get("total_count", 0), None

        async with httpx.AsyncClient(timeout=self.timeout_seconds - 3) as client:
            results = await asyncio.gather(*(search_extension(client, ext) for ext in _SECRET_PRONE_EXTENSIONS))

        matches: list[GitSecretMatch] = []
        total_count = 0
        last_error: str | None = None
        for items, count, error in results:
            total_count += count
            if error:
                last_error = error
            for item in items:
                matches.append(GitSecretMatch(
                    repository=item.get("repository", {}).get("full_name", "?"),
                    path=item.get("path", "?"),
                    url=item.get("html_url", ""),
                ))

        if not matches and last_error:
            return self.Output(query=data.query, success=False, error=last_error)

        return self.Output(
            query=data.query, success=True, total_matches_reported_by_github=total_count,
            matches=matches[:30],
        )
