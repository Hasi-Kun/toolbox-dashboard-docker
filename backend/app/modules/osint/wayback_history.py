import httpx
from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname

MAX_SNAPSHOTS = 30


@register_module
class WaybackHistoryModule(ToolModule):
    slug = "wayback-history"
    category = "osint"
    name = "Wayback Machine History"
    description = (
        f"Zeigt bis zu {MAX_SNAPSHOTS} historische Snapshots einer Domain aus der Wayback Machine "
        "(archive.org) -- nuetzlich um Infrastrukturaenderungen oder fruehere Inhalte nachzuvollziehen."
    )
    is_active_scan = False
    timeout_seconds = 15

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
            if not is_valid_hostname(v):
                raise ValueError("Ungueltige Domain")
            return v

    class Snapshot(BaseModel):
        timestamp: str
        url: str
        status_code: str | None
        archive_url: str

    class Output(BaseModel):
        domain: str
        success: bool
        total_snapshots_shown: int
        first_seen: str | None = None
        last_seen: str | None = None
        snapshots: list["WaybackHistoryModule.Snapshot"] = []
        error: str | None = None

    async def run(self, data: Input) -> Output:
        url = (
            f"http://web.archive.org/cdx/search/cdx?url={data.domain}&output=json"
            f"&limit={MAX_SNAPSHOTS}&collapse=timestamp:8&filter=statuscode:200"
        )
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.get(url, headers={"User-Agent": "Toolbox-WaybackLookup/1.0"})
        except httpx.HTTPError as exc:
            return self.Output(domain=data.domain, success=False, total_snapshots_shown=0, error=str(exc))

        if response.status_code == 429:
            return self.Output(
                domain=data.domain, success=False, total_snapshots_shown=0,
                error="Wayback Machine hat die Anfrage rate-limitiert (HTTP 429) -- spaeter erneut versuchen.",
            )
        if response.status_code != 200:
            return self.Output(
                domain=data.domain, success=False, total_snapshots_shown=0,
                error=f"Wayback Machine antwortete mit HTTP {response.status_code}",
            )

        try:
            rows = response.json()
        except ValueError:
            return self.Output(domain=data.domain, success=False, total_snapshots_shown=0, error="Antwort konnte nicht als JSON gelesen werden")

        if not rows or len(rows) < 2:
            return self.Output(domain=data.domain, success=True, total_snapshots_shown=0)

        header = rows[0]
        data_rows = rows[1:]
        idx = {name: i for i, name in enumerate(header)}

        snapshots = []
        for row in data_rows:
            timestamp = row[idx["timestamp"]]
            original_url = row[idx["original"]]
            status = row[idx["statuscode"]] if "statuscode" in idx else None
            snapshots.append(
                self.Snapshot(
                    timestamp=timestamp, url=original_url, status_code=status,
                    archive_url=f"https://web.archive.org/web/{timestamp}/{original_url}",
                )
            )

        return self.Output(
            domain=data.domain, success=True, total_snapshots_shown=len(snapshots),
            first_seen=snapshots[0].timestamp if snapshots else None,
            last_seen=snapshots[-1].timestamp if snapshots else None,
            snapshots=snapshots, error=None,
        )
