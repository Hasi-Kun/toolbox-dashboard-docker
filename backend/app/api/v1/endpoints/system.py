import logging
from datetime import datetime, timezone

import httpx
import psutil
from fastapi import APIRouter, Depends, HTTPException

from app.api.deps import require_admin
from app.core.config import get_settings
from app.models.user import User

logger = logging.getLogger("toolbox.system")
settings = get_settings()
router = APIRouter(prefix="/system", tags=["system"])


@router.get("/info")
async def system_info(_admin: User = Depends(require_admin)) -> dict:
    """CPU/RAM/Uptime wie von INNERHALB des Containers sichtbar (via /proc,
    das der Host-Kernel bereitstellt). Ohne explizite cgroup-Limits auf dem
    Container entspricht das den echten Host-Werten -- mit Limits koennen
    die Werte abweichen. Bewusst admin-only, da das ueber den Toolbox-
    eigenen Betrieb hinaus Einblick in den gesamten Host gibt.
    """
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    boot_time = datetime.fromtimestamp(psutil.boot_time(), tz=timezone.utc)
    uptime_seconds = int((datetime.now(timezone.utc) - boot_time).total_seconds())

    return {
        "cpu_percent": psutil.cpu_percent(interval=0.3),
        "cpu_count": psutil.cpu_count(),
        "memory_total_bytes": memory.total,
        "memory_used_bytes": memory.used,
        "memory_percent": memory.percent,
        "disk_total_bytes": disk.total,
        "disk_used_bytes": disk.used,
        "disk_percent": disk.percent,
        "uptime_seconds": uptime_seconds,
    }


@router.get("/docker")
async def docker_status(_admin: User = Depends(require_admin)) -> dict:
    """Container-Liste ueber den read-only Docker-Socket-Proxy (siehe
    docker-compose.yml + docs/ARCHITECTURE.md) -- das Backend selbst
    beruehrt niemals /var/run/docker.sock direkt.
    """
    url = f"{settings.docker_proxy_url}/containers/json?all=1"
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.get(url)
            response.raise_for_status()
    except httpx.HTTPError as exc:
        logger.warning("Docker-Socket-Proxy nicht erreichbar: %s", exc)
        raise HTTPException(status_code=502, detail="Docker-Status nicht erreichbar") from exc

    containers = response.json()
    return {
        "containers": [
            {
                "name": c.get("Names", ["?"])[0].lstrip("/"),
                "image": c.get("Image"),
                "state": c.get("State"),
                "status": c.get("Status"),
            }
            for c in containers
        ],
        "total": len(containers),
        "running": sum(1 for c in containers if c.get("State") == "running"),
    }
