from fastapi import APIRouter

router = APIRouter()


@router.get("/health", tags=["system"])
async def health() -> dict:
    """Liveness/Readiness-Check fuer Docker Healthcheck und Monitoring."""
    return {"status": "ok"}
