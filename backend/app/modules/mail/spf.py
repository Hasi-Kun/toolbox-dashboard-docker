from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname, query

LOOKUP_MECHANISMS = {"include", "a", "mx", "exists", "ptr", "redirect"}
QUALIFIERS = {"+", "-", "~", "?"}


class SpfMechanism(BaseModel):
    qualifier: str
    mechanism: str
    value: str | None


@register_module
class SpfCheckModule(ToolModule):
    slug = "spf-check"
    category = "mail"
    name = "SPF Analyse"
    description = "Prueft und zerlegt den SPF-Record einer Domain in seine Mechanismen."
    is_active_scan = False
    timeout_seconds = 5

    class Input(BaseModel):
        domain: str

        @field_validator("domain")
        @classmethod
        def validate_domain(cls, v: str) -> str:
            v = v.strip().rstrip(".")
            if not is_valid_hostname(v):
                raise ValueError("Ungueltiger Hostname")
            return v

    class Output(BaseModel):
        domain: str
        found: bool
        raw_record: str | None
        mechanisms: list[SpfMechanism]
        lookup_count: int
        warnings: list[str]
        error: str | None

    async def run(self, data: Input) -> Output:
        result = await query(data.domain, "TXT", timeout=self.timeout_seconds)
        if not result["success"]:
            return self.Output(
                domain=data.domain, found=False, raw_record=None,
                mechanisms=[], lookup_count=0, warnings=[], error=result["error"],
            )

        spf_records = [
            r.strip('"') for r in result["records"] if r.strip('"').startswith("v=spf1")
        ]

        if not spf_records:
            return self.Output(
                domain=data.domain, found=False, raw_record=None,
                mechanisms=[], lookup_count=0,
                warnings=["Kein SPF-Record gefunden"], error=None,
            )

        warnings: list[str] = []
        if len(spf_records) > 1:
            warnings.append(
                f"{len(spf_records)} SPF-Records gefunden -- RFC 7208 erlaubt nur genau "
                "einen. Mailserver werten das als Fehler."
            )

        raw = spf_records[0]
        mechanisms = self._parse(raw)

        lookup_count = sum(1 for m in mechanisms if m.mechanism in LOOKUP_MECHANISMS)
        if lookup_count > 10:
            warnings.append(
                f"{lookup_count} DNS-Lookups im SPF-Record -- RFC 7208 erlaubt maximal 10. "
                "Manche Empfaenger lehnen die Pruefung als PermError ab."
            )

        if not any(m.mechanism == "all" for m in mechanisms):
            warnings.append(
                "Kein 'all'-Mechanismus am Ende -- Verhalten fuer nicht gelistete "
                "Server ist undefiniert."
            )

        return self.Output(
            domain=data.domain, found=True, raw_record=raw,
            mechanisms=mechanisms, lookup_count=lookup_count,
            warnings=warnings, error=None,
        )

    @staticmethod
    def _parse(raw: str) -> list[SpfMechanism]:
        tokens = raw.split()[1:]  # "v=spf1" ueberspringen
        parsed: list[SpfMechanism] = []

        for token in tokens:
            qualifier = "+"
            if token and token[0] in QUALIFIERS:
                qualifier, token = token[0], token[1:]

            if ":" in token:
                mechanism, value = token.split(":", 1)
            elif "=" in token:
                mechanism, value = token.split("=", 1)
            else:
                mechanism, value = token, None

            parsed.append(SpfMechanism(qualifier=qualifier, mechanism=mechanism, value=value))

        return parsed
