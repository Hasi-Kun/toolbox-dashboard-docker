import httpx
from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname, is_valid_ip
from app.modules.security.common import build_client


class RobotsRule(BaseModel):
    user_agent: str
    disallow: list[str]
    allow: list[str]


@register_module
class RobotsTxtModule(ToolModule):
    slug = "robots-txt"
    category = "security"
    name = "robots.txt Check"
    description = "Ruft robots.txt ab und listet Disallow/Allow-Regeln sowie Sitemaps."
    is_active_scan = False
    timeout_seconds = 8

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
        rules: list[RobotsRule] = []
        sitemaps: list[str] = []
        raw: str | None = None
        error: str | None = None

    async def run(self, data: Input) -> Output:
        url = f"https://{data.domain}/robots.txt"
        try:
            async with build_client(timeout=self.timeout_seconds) as client:
                response = await client.get(url)
        except httpx.HTTPError as exc:
            return self.Output(domain=data.domain, found=False, error=str(exc))

        if response.status_code != 200:
            return self.Output(domain=data.domain, found=False, error=f"HTTP {response.status_code}")

        raw = response.text
        rules, sitemaps = self._parse(raw)
        return self.Output(domain=data.domain, found=True, rules=rules, sitemaps=sitemaps, raw=raw)

    @staticmethod
    def _parse(raw: str) -> tuple[list[RobotsRule], list[str]]:
        rules: list[RobotsRule] = []
        sitemaps: list[str] = []

        current_agent: str | None = None
        current_disallow: list[str] = []
        current_allow: list[str] = []

        def flush() -> None:
            if current_agent is not None:
                rules.append(RobotsRule(user_agent=current_agent, disallow=list(current_disallow), allow=list(current_allow)))

        for raw_line in raw.splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if not line or ":" not in line:
                continue
            key, _, value = line.partition(":")
            key = key.strip().lower()
            value = value.strip()

            if key == "user-agent":
                if current_agent is not None:
                    flush()
                current_agent = value
                current_disallow = []
                current_allow = []
            elif key == "disallow" and current_agent is not None:
                current_disallow.append(value)
            elif key == "allow" and current_agent is not None:
                current_allow.append(value)
            elif key == "sitemap":
                sitemaps.append(value)

        flush()
        return rules, sitemaps
