import httpx
from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname, is_valid_ip
from app.modules.security.common import build_client


@register_module
class SecurityTxtModule(ToolModule):
    slug = "security-txt"
    category = "security"
    name = "security.txt Check"
    description = "Prueft auf ein RFC-9116-konformes /.well-known/security.txt."
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
        contact: list[str] = []
        expires: str | None = None
        policy: str | None = None
        preferred_languages: str | None = None
        raw: str | None = None
        warnings: list[str] = []
        error: str | None = None

    async def run(self, data: Input) -> Output:
        for path in ("/.well-known/security.txt", "/security.txt"):
            url = f"https://{data.domain}{path}"
            try:
                async with build_client(timeout=self.timeout_seconds) as client:
                    response = await client.get(url)
            except httpx.HTTPError as exc:
                return self.Output(domain=data.domain, found=False, error=str(exc))

            if response.status_code == 200 and "contact" in response.text.lower():
                return self._parse(data.domain, response.text)

        return self.Output(
            domain=data.domain, found=False,
            warnings=["Kein security.txt gefunden -- empfohlen fuer verantwortungsvolle Offenlegung von Sicherheitsluecken (RFC 9116)."],
        )

    @classmethod
    def _parse(cls, domain: str, raw: str) -> "SecurityTxtModule.Output":
        contact: list[str] = []
        expires = None
        policy = None
        preferred_languages = None

        for raw_line in raw.splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if not line or ":" not in line:
                continue
            key, _, value = line.partition(":")
            key = key.strip().lower()
            value = value.strip()

            if key == "contact":
                contact.append(value)
            elif key == "expires":
                expires = value
            elif key == "policy":
                policy = value
            elif key == "preferred-languages":
                preferred_languages = value

        warnings: list[str] = []
        if not contact:
            warnings.append("Kein 'Contact'-Feld gefunden -- Pflichtfeld nach RFC 9116.")
        if not expires:
            warnings.append("Kein 'Expires'-Feld gefunden -- Pflichtfeld nach RFC 9116.")

        return cls.Output(
            domain=domain, found=True, contact=contact, expires=expires,
            policy=policy, preferred_languages=preferred_languages, raw=raw, warnings=warnings,
        )
