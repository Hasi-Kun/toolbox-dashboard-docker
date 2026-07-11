from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.db import get_db
from app.core.sessions import get_session_user_id, refresh_session_ttl
from app.models.user import User, UserRole

settings = get_settings()


async def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    session_id = request.cookies.get(settings.session_cookie_name)
    if not session_id:
        raise HTTPException(status_code=401, detail="Nicht angemeldet")

    user_id = await get_session_user_id(session_id)
    if user_id is None:
        raise HTTPException(status_code=401, detail="Session abgelaufen oder ungueltig")

    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="Account nicht (mehr) aktiv")

    # Gleitende Sitzungsverlaengerung ("automatischer Logout nach
    # Inaktivitaet"): bei jeder authentifizierten Anfrage die Session-TTL
    # auf den individuellen (falls gesetzt) oder globalen Timeout
    # zurueckSetzen, statt sie nach einer festen Zeit ab dem Login
    # ablaufen zu lassen.
    effective_timeout_seconds = (
        user.session_timeout_minutes * 60 if user.session_timeout_minutes else settings.session_ttl_seconds
    )
    await refresh_session_ttl(session_id, user.id, effective_timeout_seconds)

    return user


async def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != UserRole.ADMIN.value:
        raise HTTPException(status_code=403, detail="Nur fuer Administratoren")
    return user
