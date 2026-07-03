from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.db import get_db
from app.core.sessions import get_session_user_id
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

    return user


async def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != UserRole.ADMIN.value:
        raise HTTPException(status_code=403, detail="Nur fuer Administratoren")
    return user
