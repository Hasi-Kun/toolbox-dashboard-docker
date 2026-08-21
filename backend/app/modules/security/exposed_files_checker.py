"""Prueft eine Website auf oeffentlich erreichbare, sensible Dateien
(.env, .git/config, Backup-/Config-Dateien u.ae.) -- rein passiv:
schickt fuer jeden bekannten Pfad einen einzelnen GET-Request und prueft
den Statuscode plus ein paar einfache Inhalts-Heuristiken (z.B. "DB_
PASSWORD=" in einer vermeintlichen .env-Datei), um False-Positives durch
individuelle 200-OK-Fehlerseiten (SPA-Routing, Custom-404 mit Status 200)
zu vermeiden.
"""

import asyncio
import secrets

import httpx
from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname, is_valid_ip

# Bewusst eine kleine, dokumentierte Liste haeufiger, sensibler Pfade --
# kein erschoepfender Wortlisten-Scan (das waere ein aktiver Bruteforce-
# Scan gegen fremde Server, nicht mehr die gezielte Pruefung auf die
# bekanntesten, folgenschwersten Fehlkonfigurationen).
_SENSITIVE_PATHS: list[tuple[str, str]] = [
    (".env", "generic"),
    (".env.local", "generic"),
    (".env.production", "generic"),
    (".env.backup", "generic"),
    (".git/config", "git"),
    (".git/HEAD", "git"),
    (".htaccess", "generic"),
    ("wp-config.php", "generic"),
    ("wp-config.php.bak", "generic"),
    ("config.php.bak", "generic"),
    ("config.yml", "generic"),
    ("docker-compose.yml", "generic"),
    ("composer.json", "generic"),
    ("package.json", "generic"),
    (".npmrc", "generic"),
    ("id_rsa", "keyfile"),
    (".DS_Store", "generic"),
    ("backup.sql", "generic"),
    ("dump.sql", "generic"),
    ("database.sql", "generic"),
    (".aws/credentials", "generic"),
]

# Inhalts-Heuristiken pro Kategorie -- mindestens EIN Treffer noetig,
# damit ein 200-OK auch tatsaechlich als Fund gilt (statt nur als
# generische "alles ist 200"-Fehlseite einer SPA/eines CMS).
_CONTENT_HINTS: dict[str, list[str]] = {
    "generic": ["password", "secret", "api_key", "token", "db_", "database_url", "private"],
    "git": ["ref:", "[core]", "repositoryformatversion"],
    "keyfile": ["-----begin", "private key"],
}


class ExposedFileResult(BaseModel):
    path: str
    status_code: int
    content_length: int | None = None
    likely_exposed: bool


@register_module
class ExposedFilesCheckerModule(ToolModule):
    slug = "exposed-files-checker"
    category = "security"
    name = "Exponierte-Dateien-Checker (.env-Scanner)"
    description = (
        "Prueft eine Website auf oeffentlich erreichbare, sensible Dateien (.env, .git/config, "
        "Backup-/Config-Dateien u.ae.) -- rein passive GET-Requests gegen eine kleine, dokumentierte "
        "Liste bekannter Pfade, mit Inhalts-Heuristik gegen False-Positives durch generische "
        "200-OK-Fehlerseiten."
    )
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
        paths_checked: int = 0
        exposed: list[ExposedFileResult] = []
        error: str | None = None

    async def run(self, data: Input) -> Output:
        # Baseline: eine garantiert nicht existierende Zufalls-URL abfragen,
        # um den echten "nicht gefunden"-Statuscode/-Antwortlaenge dieser
        # konkreten Seite zu kennen -- manche Server antworten auf ALLES
        # mit 200 (SPA-Routing/Custom-Fehlerseiten). Ohne diesen Vergleich
        # wuerden solche Seiten faelschlich JEDEN Pfad als "exponiert" zeigen.
        baseline_path = f"toolbox-baseline-check-{secrets.token_hex(8)}.txt"

        async def fetch(client: httpx.AsyncClient, path: str) -> httpx.Response | None:
            try:
                return await client.get(f"https://{data.domain}/{path}", headers={"User-Agent": "Toolbox-Exposed-Files-Check/1.0"})
            except httpx.HTTPError:
                return None

        try:
            async with httpx.AsyncClient(timeout=6.0, follow_redirects=False) as client:
                baseline_response = await fetch(client, baseline_path)
                baseline_status = baseline_response.status_code if baseline_response else None
                baseline_length = len(baseline_response.content) if baseline_response else None

                tasks = [fetch(client, path) for path, _category in _SENSITIVE_PATHS]
                responses = await asyncio.gather(*tasks)
        except Exception as exc:  # noqa: BLE001
            return self.Output(domain=data.domain, success=False, error=str(exc))

        exposed = []
        for (path, category), response in zip(_SENSITIVE_PATHS, responses):
            if response is None:
                continue
            # Wenn der Server "immer 200" antwortet (SPA-Routing o.ae.),
            # nur noch als Fund werten, wenn sich die Antwort deutlich
            # von der Baseline unterscheidet (andere Laenge) UND die
            # Inhalts-Heuristik zutrifft.
            same_as_baseline = response.status_code == baseline_status and len(response.content) == baseline_length
            if response.status_code != 200 or same_as_baseline:
                continue

            body_lower = response.text.lower()[:5000]
            hints = _CONTENT_HINTS.get(category, [])
            content_matches = any(hint in body_lower for hint in hints)

            # Fuer eindeutig riskante Pfade (z.B. .git/HEAD, id_rsa) reicht
            # ein simples 200 (kein generisches Content-Hint-System noetig,
            # die Pfade selbst sind bereits eindeutig), fuer generische
            # Pfade wie .env/config.yml zusaetzlich die Inhalts-Heuristik.
            likely_exposed = content_matches or category in ("git", "keyfile") or path in (".env", ".env.local", ".env.production", ".env.backup")

            exposed.append(ExposedFileResult(
                path=path, status_code=response.status_code,
                content_length=len(response.content), likely_exposed=likely_exposed,
            ))

        return self.Output(domain=data.domain, success=True, paths_checked=len(_SENSITIVE_PATHS), exposed=exposed)
