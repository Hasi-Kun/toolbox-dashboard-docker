from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname, query


@register_module
class DmarcCheckModule(ToolModule):
    slug = "dmarc-check"
    category = "mail"
    name = "DMARC Analyse"
    description = "Prueft und interpretiert den DMARC-Record einer Domain."
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
        policy: str | None
        subdomain_policy: str | None
        percentage: int | None
        aggregate_reports: list[str]
        forensic_reports: list[str]
        warnings: list[str]
        strength_score: int = 0
        strength_label: str = "kein DMARC"
        error: str | None

    async def run(self, data: Input) -> Output:
        query_name = f"_dmarc.{data.domain}"
        result = await query(query_name, "TXT", timeout=self.timeout_seconds)

        if not result["success"]:
            return self._empty(data.domain, error=result["error"])

        dmarc_records = [
            r.strip('"') for r in result["records"] if r.strip('"').startswith("v=DMARC1")
        ]
        if not dmarc_records:
            return self._empty(data.domain, warnings=["Kein DMARC-Record gefunden"])

        warnings: list[str] = []
        if len(dmarc_records) > 1:
            warnings.append(
                f"{len(dmarc_records)} DMARC-Records gefunden -- es sollte nur genau "
                "einer existieren."
            )

        raw = dmarc_records[0]
        return self._parse_record(data.domain, raw, extra_warnings=warnings)

    @classmethod
    def _parse_record(
        cls, domain: str, raw: str, extra_warnings: list[str]
    ) -> "DmarcCheckModule.Output":
        tags = dict(
            part.strip().split("=", 1) for part in raw.split(";") if "=" in part.strip()
        )

        policy = tags.get("p")
        subdomain_policy = tags.get("sp", policy)
        pct_raw = tags.get("pct")
        percentage = int(pct_raw) if pct_raw and pct_raw.isdigit() else 100

        warnings = list(extra_warnings)
        if policy == "none":
            warnings.append(
                "Policy ist 'none' -- DMARC ueberwacht nur, blockiert aber keine "
                "gefaelschten Mails."
            )
        if percentage < 100:
            warnings.append(f"Nur {percentage}% der Mails werden gemaess Policy behandelt.")

        aggregate_reports = cls._parse_reports(tags.get("rua"))
        strength_score, strength_label = cls._compute_strength(policy, percentage, bool(aggregate_reports))

        return cls.Output(
            domain=domain, found=True, raw_record=raw, policy=policy,
            subdomain_policy=subdomain_policy, percentage=percentage,
            aggregate_reports=aggregate_reports,
            forensic_reports=cls._parse_reports(tags.get("ruf")),
            warnings=warnings, strength_score=strength_score, strength_label=strength_label, error=None,
        )

    @staticmethod
    def _compute_strength(policy: str | None, percentage: int, has_aggregate_reports: bool) -> tuple[int, str]:
        """Grobe Staerke-Einschaetzung: p=reject > quarantine > none,
        skaliert mit dem pct-Anteil, kleiner Bonus fuer aktives
        Reporting (rua) -- rein informativ, kein Ersatz fuer eine
        vollstaendige Bewertung."""
        base_by_policy = {"reject": 90, "quarantine": 60, "none": 30}
        base = base_by_policy.get(policy or "", 0)
        score = round(base * (percentage / 100))
        if has_aggregate_reports:
            score = min(100, score + 10)

        if score >= 80:
            label = "stark"
        elif score >= 50:
            label = "mittel"
        elif score > 0:
            label = "schwach"
        else:
            label = "kein DMARC"
        return score, label

    def _empty(
        self, domain: str, warnings: list[str] | None = None, error: str | None = None
    ) -> "DmarcCheckModule.Output":
        return self.Output(
            domain=domain, found=False, raw_record=None, policy=None,
            subdomain_policy=None, percentage=None, aggregate_reports=[],
            forensic_reports=[], warnings=warnings or [], error=error,
        )

    @staticmethod
    def _parse_reports(value: str | None) -> list[str]:
        if not value:
            return []
        return [v.strip() for v in value.split(",") if v.strip()]
