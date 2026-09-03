"""CVE Lookup: ruft Details zu einer bekannten CVE-ID von der NVD
(National Vulnerability Database, NIST) ab -- kostenlos, kein API-Key
noetig fuer Einzelabfragen (rate-limitiert auf 5 Anfragen/30s ohne
Key, fuer eine Einzel-Lookup-Anwendung ausreichend).
"""

import re

import httpx
from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module

_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@register_module
class CveLookupModule(ToolModule):
    slug = "cve-lookup"
    category = "osint"
    name = "CVE Lookup"
    description = "Ruft Details zu einer CVE-ID von der NVD (NIST) ab -- Beschreibung, CVSS-Score, betroffene Produkte, Referenzen."
    is_active_scan = False
    timeout_seconds = 12

    class Input(BaseModel):
        cve_id: str

        @field_validator("cve_id")
        @classmethod
        def validate_cve_id(cls, v: str) -> str:
            v = v.strip().upper()
            if not _CVE_ID_RE.match(v):
                raise ValueError("Ungueltiges Format -- erwartet z.B. CVE-2021-44228")
            return v

    class CvssScore(BaseModel):
        version: str
        base_score: float
        base_severity: str
        vector_string: str

    class Reference(BaseModel):
        url: str
        source: str | None = None

    class Output(BaseModel):
        cve_id: str
        found: bool
        description: str | None = None
        published: str | None = None
        last_modified: str | None = None
        cvss: list["CveLookupModule.CvssScore"] = []
        cwe_ids: list[str] = []
        references: list["CveLookupModule.Reference"] = []
        error: str | None = None

    async def run(self, data: "CveLookupModule.Input") -> "CveLookupModule.Output":
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.get(_NVD_API_URL, params={"cveId": data.cve_id})
        except httpx.HTTPError as exc:
            return self.Output(cve_id=data.cve_id, found=False, error=f"NVD nicht erreichbar: {exc}")

        if response.status_code == 404:
            return self.Output(cve_id=data.cve_id, found=False, error="CVE nicht gefunden")
        if response.status_code == 429:
            return self.Output(cve_id=data.cve_id, found=False, error="NVD-Rate-Limit erreicht -- bitte kurz warten und erneut versuchen")
        if response.status_code != 200:
            return self.Output(cve_id=data.cve_id, found=False, error=f"NVD antwortete mit HTTP {response.status_code}")

        try:
            body = response.json()
        except ValueError:
            return self.Output(cve_id=data.cve_id, found=False, error="Antwort der NVD konnte nicht gelesen werden")

        vulns = body.get("vulnerabilities", [])
        if not vulns:
            return self.Output(cve_id=data.cve_id, found=False, error="CVE nicht gefunden")

        cve = vulns[0].get("cve", {})

        description = None
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value")
                break

        cvss_scores: list[CveLookupModule.CvssScore] = []
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            for entry in metrics.get(key, []):
                cvss_data = entry.get("cvssData", {})
                cvss_scores.append(
                    self.CvssScore(
                        version=cvss_data.get("version", "?"),
                        base_score=cvss_data.get("baseScore", 0.0),
                        base_severity=cvss_data.get("baseSeverity") or entry.get("baseSeverity", "UNKNOWN"),
                        vector_string=cvss_data.get("vectorString", ""),
                    )
                )
            if cvss_scores:
                break  # bevorzugt die neueste verfuegbare CVSS-Version, nicht alle gleichzeitig

        cwe_ids = []
        for weakness in cve.get("weaknesses", []):
            for desc in weakness.get("description", []):
                if desc.get("value", "").startswith("CWE-"):
                    cwe_ids.append(desc["value"])

        references = [
            self.Reference(url=ref.get("url", ""), source=ref.get("source"))
            for ref in cve.get("references", [])[:15]
        ]

        return self.Output(
            cve_id=data.cve_id, found=True, description=description,
            published=cve.get("published"), last_modified=cve.get("lastModified"),
            cvss=cvss_scores, cwe_ids=list(dict.fromkeys(cwe_ids)), references=references,
        )
