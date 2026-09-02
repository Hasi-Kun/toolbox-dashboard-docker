"""Curl Browser Tool: HTTP-Anfragen ueber eine GUI zusammenstellen und
ausfuehren -- Methode/Header/Body waehlen, Ergebnis UND den
aequivalenten curl-Befehl sehen (zum Kopieren/Weiterverwenden auf der
Kommandozeile).

Bewusst admin-only: erlaubt beliebige HTTP-Methoden (inkl. POST/PUT/
DELETE mit Body) gegen selbst gewaehlte Ziele -- potenziell
seiteneffektbehaftete Anfragen, aehnlich anderen admin-only Tools in
dieser Toolbox (z.B. SMTP-Debug). Keine strikte SSRF-Sperre gegen
interne/private Ziele -- konsistent mit dem etablierten Muster anderer
HTTP-abfragender Tools dieser Toolbox (z.B. redirect-chain), die
authentifizierten Nutzern bewusst erlauben, auch eigene interne
Systeme zu pruefen.
"""

import shlex
import time
from typing import Literal

import httpx
from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname, is_valid_ip

MAX_BODY_CHARS = 200_000
MAX_REQUEST_BODY_CHARS = 100_000


def _build_curl_command(method: str, url: str, headers: list[tuple[str, str]], body: str | None) -> str:
    parts = ["curl", "-i", "-sS", "-X", shlex.quote(method)]
    for key, value in headers:
        parts += ["-H", shlex.quote(f"{key}: {value}")]
    if body:
        parts += ["--data-raw", shlex.quote(body)]
    parts.append(shlex.quote(url))
    return " ".join(parts)


@register_module
class HttpRequestModule(ToolModule):
    slug = "curl-browser"
    category = "website"
    name = "Curl Browser Tool"
    description = "HTTP-Anfragen per GUI zusammenstellen und ausfuehren -- inkl. des aequivalenten curl-Befehls."
    is_active_scan = False
    requires_admin = True
    timeout_seconds = 20

    class HeaderPair(BaseModel):
        key: str
        value: str

    class Input(BaseModel):
        method: Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] = "GET"
        url: str
        headers: list["HttpRequestModule.HeaderPair"] = []
        body: str | None = None
        follow_redirects: bool = True

        @field_validator("url")
        @classmethod
        def validate_url(cls, v: str) -> str:
            v = v.strip()
            if not v.startswith(("http://", "https://")):
                v = f"https://{v}"
            host = v.split("://", 1)[1].split("/")[0].split("@")[-1].split(":")[0]
            if not (is_valid_hostname(host) or is_valid_ip(host)):
                raise ValueError("Ungueltige URL")
            return v

        @field_validator("body")
        @classmethod
        def validate_body(cls, v: str | None) -> str | None:
            if v is not None and len(v) > MAX_REQUEST_BODY_CHARS:
                raise ValueError(f"Body zu lang (max. {MAX_REQUEST_BODY_CHARS} Zeichen)")
            return v

        @field_validator("headers")
        @classmethod
        def validate_headers(cls, v: list["HttpRequestModule.HeaderPair"]) -> list["HttpRequestModule.HeaderPair"]:
            if len(v) > 30:
                raise ValueError("Maximal 30 Header")
            return v

    class Output(BaseModel):
        status_code: int | None = None
        response_headers: dict[str, str] = {}
        response_body: str = ""
        body_truncated: bool = False
        elapsed_ms: float = 0
        curl_command: str
        error: str | None = None

    async def run(self, data: "HttpRequestModule.Input") -> "HttpRequestModule.Output":
        header_pairs = [(h.key, h.value) for h in data.headers]
        curl_command = _build_curl_command(data.method, data.url, header_pairs, data.body)

        try:
            start = time.monotonic()
            async with httpx.AsyncClient(
                timeout=self.timeout_seconds, follow_redirects=data.follow_redirects, verify=False
            ) as client:
                response = await client.request(
                    data.method, data.url, headers=dict(header_pairs),
                    content=data.body.encode("utf-8") if data.body else None,
                )
            elapsed_ms = (time.monotonic() - start) * 1000

            body_text = response.text
            truncated = len(body_text) > MAX_BODY_CHARS
            if truncated:
                body_text = body_text[:MAX_BODY_CHARS]

            return self.Output(
                status_code=response.status_code,
                response_headers=dict(response.headers),
                response_body=body_text,
                body_truncated=truncated,
                elapsed_ms=round(elapsed_ms, 1),
                curl_command=curl_command,
            )
        except httpx.TimeoutException:
            return self.Output(curl_command=curl_command, error=f"Zeitueberschreitung nach {self.timeout_seconds}s")
        except httpx.HTTPError as exc:
            return self.Output(curl_command=curl_command, error=str(exc))
