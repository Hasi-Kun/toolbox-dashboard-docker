import httpx
from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname, is_valid_ip


@register_module
class IpGeolocationModule(ToolModule):
    slug = "ip-geolocation"
    category = "utilities"
    name = "IP Geolocation Lookup"
    description = "Ermittelt Standort, ISP und Organisation einer IP/Domain (ueber ip-api.com, kein API-Key noetig) inkl. Karten-Link."
    is_active_scan = False
    timeout_seconds = 8

    class Input(BaseModel):
        target: str

        @field_validator("target")
        @classmethod
        def validate_target(cls, v: str) -> str:
            v = v.strip().rstrip(".")
            if not (is_valid_hostname(v) or is_valid_ip(v)):
                raise ValueError("Ungueltiges Ziel (Domain oder IP erwartet)")
            return v

    class Output(BaseModel):
        target: str
        success: bool
        ip: str | None = None
        country: str | None = None
        region: str | None = None
        city: str | None = None
        zip_code: str | None = None
        latitude: float | None = None
        longitude: float | None = None
        timezone: str | None = None
        isp: str | None = None
        organization: str | None = None
        map_embed_url: str | None = None
        error: str | None = None

    async def run(self, data: Input) -> Output:
        # ip-api.com bietet die kostenlose JSON-Schnittstelle nur ueber HTTP an
        # (HTTPS ist Teil des kostenpflichtigen Plans) -- unproblematisch, da
        # hier nur oeffentliche Geolocation-Daten abgefragt werden, keine
        # sensiblen Inhalte.
        url = f"http://ip-api.com/json/{data.target}?fields=status,message,country,regionName,city,zip,lat,lon,timezone,isp,org,query"

        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.get(url)
                payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            return self.Output(target=data.target, success=False, error=str(exc))

        if payload.get("status") != "success":
            return self.Output(target=data.target, success=False, error=payload.get("message", "Lookup fehlgeschlagen"))

        lat, lon = payload.get("lat"), payload.get("lon")
        map_url = None
        if lat is not None and lon is not None:
            map_url = (
                f"https://www.openstreetmap.org/export/embed.html?"
                f"bbox={lon - 0.1}%2C{lat - 0.1}%2C{lon + 0.1}%2C{lat + 0.1}&layer=mapnik&marker={lat}%2C{lon}"
            )

        return self.Output(
            target=data.target, success=True, ip=payload.get("query"),
            country=payload.get("country"), region=payload.get("regionName"),
            city=payload.get("city"), zip_code=payload.get("zip"),
            latitude=lat, longitude=lon, timezone=payload.get("timezone"),
            isp=payload.get("isp"), organization=payload.get("org"),
            map_embed_url=map_url, error=None,
        )
