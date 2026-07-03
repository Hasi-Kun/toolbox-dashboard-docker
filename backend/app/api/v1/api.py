from fastapi import APIRouter

from app.api.v1.endpoints import account, appearance, auth, health, system, tools, users

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(account.router, prefix="/auth", tags=["account"])
api_router.include_router(appearance.router, tags=["appearance"])
api_router.include_router(users.router, tags=["users"])
api_router.include_router(system.router)
api_router.include_router(tools.router)

# Zukuenftige Kategorien werden hier eingehaengt, z.B.:
# from app.api.v1.endpoints import dns
# api_router.include_router(dns.router, prefix="/dns", tags=["dns"])
