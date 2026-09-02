from fastapi import APIRouter

from app.api.v1.endpoints import account, appearance, auth, canary_token_scan, chat, dns_flush, email_aliases, feature_requests, health, one_time_secrets, openssl_tool, security_settings, sso, ssh_connections, system, tools, users

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(account.router, prefix="/auth", tags=["account"])
api_router.include_router(sso.router, tags=["sso"])
api_router.include_router(appearance.router, tags=["appearance"])
api_router.include_router(security_settings.router, tags=["security-settings"])
api_router.include_router(ssh_connections.router, tags=["ssh-connections"])
api_router.include_router(canary_token_scan.router, tags=["canary-token-scan"])
api_router.include_router(one_time_secrets.router, tags=["one-time-secrets"])
api_router.include_router(email_aliases.router, tags=["email-aliases"])
api_router.include_router(dns_flush.router, tags=["dns-flush"])
api_router.include_router(users.router, tags=["users"])
api_router.include_router(system.router)
api_router.include_router(chat.router)
api_router.include_router(feature_requests.router)
api_router.include_router(openssl_tool.router)
api_router.include_router(tools.router)

# Zukuenftige Kategorien werden hier eingehaengt, z.B.:
# from app.api.v1.endpoints import dns
# api_router.include_router(dns.router, prefix="/dns", tags=["dns"])
