import asyncio

from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import COMMON_DKIM_SELECTORS, is_valid_hostname, query


class DkimSelectorResult(BaseModel):
    selector: str
    found: bool
    raw_record: str | None
    key_type: str | None
    public_key_present: bool


@register_module
class DkimCheckModule(ToolModule):
    slug = "dkim-check"
    category = "mail"
    name = "DKIM Lookup"
    description = (
        "Sucht DKIM-Records -- entweder fuer einen angegebenen Selector "
        "oder automatisch fuer eine Liste gaengiger Selectoren."
    )
    is_active_scan = False
    timeout_seconds = 8  # mehrere Selectoren parallel, etwas grosszuegigeres Limit

    class Input(BaseModel):
        domain: str
        selector: str | None = None  # None = Fallback-Liste durchprobieren

        @field_validator("domain")
        @classmethod
        def validate_domain(cls, v: str) -> str:
            v = v.strip().rstrip(".")
            if not is_valid_hostname(v):
                raise ValueError("Ungueltiger Hostname")
            return v

        @field_validator("selector")
        @classmethod
        def validate_selector(cls, v: str | None) -> str | None:
            if v is None:
                return v
            v = v.strip()
            if not v or not all(c.isalnum() or c in "-_." for c in v):
                raise ValueError("Ungueltiger Selector (nur Buchstaben, Ziffern, '-', '_', '.')")
            return v

    class Output(BaseModel):
        domain: str
        selectors_checked: list[str]
        results: list[DkimSelectorResult]
        found_any: bool

    async def run(self, data: Input) -> Output:
        selectors = [data.selector] if data.selector else list(COMMON_DKIM_SELECTORS)

        results: list[DkimSelectorResult] = await asyncio.gather(
            *(self._check_selector(data.domain, s) for s in selectors)
        )

        return self.Output(
            domain=data.domain,
            selectors_checked=selectors,
            results=list(results),
            found_any=any(r.found for r in results),
        )

    async def _check_selector(self, domain: str, selector: str) -> DkimSelectorResult:
        name = f"{selector}._domainkey.{domain}"
        result = await query(name, "TXT", timeout=5.0)

        if not result["success"] or not result["records"]:
            return DkimSelectorResult(
                selector=selector, found=False, raw_record=None,
                key_type=None, public_key_present=False,
            )

        raw = result["records"][0].strip('"')
        return self._parse_record(selector, raw)

    @staticmethod
    def _parse_record(selector: str, raw: str) -> DkimSelectorResult:
        tags = dict(part.strip().split("=", 1) for part in raw.split(";") if "=" in part)

        return DkimSelectorResult(
            selector=selector,
            found=True,
            raw_record=raw,
            key_type=tags.get("k", "rsa").strip(),
            public_key_present=bool(tags.get("p", "").strip()),
        )
