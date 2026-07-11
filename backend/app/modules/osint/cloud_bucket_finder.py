"""Generiert plausible Cloud-Storage-Bucket-Namen aus einem Firmen-/
Projektnamen und prueft, ob sie oeffentlich existieren (S3, Azure Blob,
Google Cloud Storage) -- rein passive HTTP-Anfragen, keine Anmeldedaten,
kein Schreibzugriff.
"""

import asyncio
import re

import httpx
from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module

_SUFFIXES = ["", "-backup", "-dev", "-prod", "-staging", "-static", "-assets", "-media", "-uploads", "-data", "-files", "-www", "-public", "-private", "-test"]
_MAX_CANDIDATES = 40


def _sanitize_base_name(name: str) -> str:
    name = name.lower().strip()
    # Domain-Endungen und alles ab dem ersten Punkt/Slash entfernen, damit
    # aus "example.com" sinnvoll "example" wird statt "example.com-backup".
    name = name.split("/")[0].split(".")[0]
    name = re.sub(r"[^a-z0-9-]", "", name)
    return name


class BucketCandidate(BaseModel):
    name: str
    provider: str  # "S3" | "Azure Blob" | "Google Cloud Storage"
    exists: bool
    publicly_listable: bool = False
    url: str


@register_module
class CloudBucketFinderModule(ToolModule):
    slug = "cloud-bucket-finder"
    category = "osint"
    name = "Cloud-Storage-Bucket-Finder"
    description = (
        "Generiert plausible Bucket-Namen aus einem Firmen-/Projektnamen und prueft, ob sie bei "
        "AWS S3, Azure Blob Storage oder Google Cloud Storage oeffentlich existieren -- rein passive "
        "HTTP-Anfragen, kein Schreibzugriff, keine Anmeldedaten."
    )
    is_active_scan = False
    timeout_seconds = 25

    class Input(BaseModel):
        name: str

        @field_validator("name")
        @classmethod
        def validate_name(cls, v: str) -> str:
            sanitized = _sanitize_base_name(v)
            if not sanitized or len(sanitized) < 3:
                raise ValueError("Name muss mindestens 3 gueltige Zeichen ergeben (a-z, 0-9, -)")
            return sanitized

    class Output(BaseModel):
        base_name: str
        candidates_checked: int
        found: list[BucketCandidate] = []

    async def _check_s3(self, client: httpx.AsyncClient, bucket: str) -> BucketCandidate | None:
        url = f"https://{bucket}.s3.amazonaws.com/"
        try:
            response = await client.get(url)
        except httpx.HTTPError:
            return None
        if response.status_code == 404:
            return None  # NoSuchBucket
        if response.status_code in (200, 403):
            return BucketCandidate(
                name=bucket, provider="S3", exists=True,
                publicly_listable=response.status_code == 200, url=url,
            )
        return None

    async def _check_azure(self, client: httpx.AsyncClient, bucket: str) -> BucketCandidate | None:
        url = f"https://{bucket}.blob.core.windows.net/?comp=list"
        try:
            response = await client.get(url)
        except httpx.HTTPError:
            return None
        # Azure liefert bei existierendem Account, aber ohne oeffentlichen
        # Container, einen anderen Fehlercode als bei komplett unbekanntem
        # Hostnamen (DNS-Fehler auf Verbindungsebene) -- ein HTTP-Response
        # ueberhaupt (egal welcher Code) bedeutet meist "Account existiert".
        if response.status_code == 200:
            return BucketCandidate(name=bucket, provider="Azure Blob", exists=True, publicly_listable=True, url=url)
        if response.status_code in (400, 403, 404):
            # 400/403 = Account existiert, aber kein oeffentlicher Zugriff auf Listing
            if response.status_code != 404:
                return BucketCandidate(name=bucket, provider="Azure Blob", exists=True, publicly_listable=False, url=url)
        return None

    async def _check_gcs(self, client: httpx.AsyncClient, bucket: str) -> BucketCandidate | None:
        url = f"https://storage.googleapis.com/{bucket}/"
        try:
            response = await client.get(url)
        except httpx.HTTPError:
            return None
        if response.status_code == 404:
            return None
        if response.status_code in (200, 403):
            return BucketCandidate(
                name=bucket, provider="Google Cloud Storage", exists=True,
                publicly_listable=response.status_code == 200, url=url,
            )
        return None

    async def run(self, data: Input) -> Output:
        candidates = [f"{data.name}{suffix}" for suffix in _SUFFIXES][:_MAX_CANDIDATES]

        async with httpx.AsyncClient(timeout=6.0, headers={"User-Agent": "Toolbox-Bucket-Finder/1.0"}) as client:
            tasks = []
            for candidate in candidates:
                tasks.append(self._check_s3(client, candidate))
                tasks.append(self._check_azure(client, candidate))
                tasks.append(self._check_gcs(client, candidate))
            results = await asyncio.gather(*tasks, return_exceptions=False)

        found = [r for r in results if r is not None]
        return self.Output(base_name=data.name, candidates_checked=len(candidates), found=found)
