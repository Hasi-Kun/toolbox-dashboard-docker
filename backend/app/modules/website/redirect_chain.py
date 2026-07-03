import httpx
from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname, is_valid_ip

MAX_HOPS = 10


class RedirectHop(BaseModel):
    hop: int
    url: str
    status_code: int
    location: str | None = None


@register_module
class RedirectChainModule(ToolModule):
    slug = "redirect-chain"
    category = "website"
    name = "Redirect Chain"
    description = f"Folgt Weiterleitungen Schritt fuer Schritt (max. {MAX_HOPS} Hops) und erkennt Redirect-Loops."
    is_active_scan = False
    timeout_seconds = 15

    class Input(BaseModel):
        url: str

        @field_validator("url")
        @classmethod
        def validate_url(cls, v: str) -> str:
            v = v.strip()
            if not v.startswith(("http://", "https://")):
                v = f"https://{v}"
            host = v.split("://", 1)[1].split("/")[0].split(":")[0]
            if not (is_valid_hostname(host) or is_valid_ip(host)):
                raise ValueError("Ungueltige URL")
            return v

    class Output(BaseModel):
        start_url: str
        final_url: str
        hops: list[RedirectHop]
        loop_detected: bool
        error: str | None = None

    async def run(self, data: Input) -> Output:
        hops: list[RedirectHop] = []
        seen_urls: set[str] = set()
        current_url = data.url
        loop_detected = False

        async with httpx.AsyncClient(timeout=self.timeout_seconds, follow_redirects=False, verify=False) as client:
            for i in range(MAX_HOPS):
                if current_url in seen_urls:
                    loop_detected = True
                    break
                seen_urls.add(current_url)

                try:
                    response = await client.get(current_url, headers={"User-Agent": "Toolbox-RedirectCheck/1.0"})
                except httpx.HTTPError as exc:
                    return self.Output(
                        start_url=data.url, final_url=current_url, hops=hops,
                        loop_detected=False, error=str(exc),
                    )

                location = response.headers.get("location")
                hops.append(RedirectHop(hop=i + 1, url=current_url, status_code=response.status_code, location=location))

                if response.is_redirect and location:
                    current_url = str(httpx.URL(current_url).join(location))
                else:
                    break

        return self.Output(
            start_url=data.url, final_url=current_url, hops=hops, loop_detected=loop_detected, error=None,
        )
