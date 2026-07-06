from datetime import date

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_admin
from app.core.config import get_settings
from app.core.db import get_db
from app.core.rate_limit import enforce_rate_limit
from app.models.user import AppearanceSettings, ChatMessage, User

settings = get_settings()
router = APIRouter(prefix="/chat", tags=["chat"])


def _clear_chat_if_new_day(db: Session) -> None:
    """Leert die Shoutbox einmal taeglich (beim ersten Request nach
    Mitternacht UTC) -- kein Scheduler-Prozess noetig, da Chat-Nachrichten
    ohnehin per Polling alle paar Sekunden abgefragt werden.
    """
    today = date.today().isoformat()
    appearance = db.get(AppearanceSettings, 1)
    if appearance is None:
        appearance = AppearanceSettings(id=1, chat_last_cleared_date=today)
        db.add(appearance)
        db.commit()
        return

    if appearance.chat_last_cleared_date == today:
        return

    db.query(ChatMessage).delete()
    appearance.chat_last_cleared_date = today
    db.add(appearance)
    db.commit()


class PostMessageRequest(BaseModel):
    message: str

    @field_validator("message")
    @classmethod
    def validate_message(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Nachricht darf nicht leer sein")
        if len(v) > 500:
            raise ValueError("Nachricht darf maximal 500 Zeichen haben")
        return v


class MessageOut(BaseModel):
    id: int
    username: str
    message: str
    created_at: str
    is_own: bool = False
    is_premium: bool = False
    premium_badge_color: str = "#F5C518"


@router.get("/messages", response_model=list[MessageOut])
async def list_messages(
    limit: int = 50, db: Session = Depends(get_db), user: User = Depends(get_current_user)
) -> list[MessageOut]:
    _clear_chat_if_new_day(db)
    limit = max(1, min(limit, 100))
    messages = db.query(ChatMessage).order_by(ChatMessage.created_at.desc()).limit(limit).all()
    messages = list(reversed(messages))

    author_ids = {m.user_id for m in messages if m.user_id is not None}
    authors = {u.id: u for u in db.query(User).filter(User.id.in_(author_ids)).all()} if author_ids else {}

    return [
        MessageOut(
            id=m.id, username=m.username, message=m.message, created_at=m.created_at.isoformat(),
            is_own=m.user_id == user.id,
            is_premium=authors[m.user_id].is_premium if m.user_id in authors else False,
            premium_badge_color=authors[m.user_id].premium_badge_color if m.user_id in authors else "#F5C518",
        )
        for m in messages
    ]


@router.post("/messages", response_model=MessageOut)
async def post_message(
    payload: PostMessageRequest, request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)
) -> MessageOut:
    # Eigener, enger Rate-Limit-Bucket -- verhindert Spam/Flooding der Shoutbox
    await enforce_rate_limit(request, bucket="chat-post", limit=20)
    _clear_chat_if_new_day(db)

    msg = ChatMessage(user_id=user.id, username=user.username, message=payload.message)
    db.add(msg)
    db.commit()
    db.refresh(msg)
    return MessageOut(
        id=msg.id, username=msg.username, message=msg.message, created_at=msg.created_at.isoformat(), is_own=True,
        is_premium=user.is_premium, premium_badge_color=user.premium_badge_color,
    )


@router.delete("/messages/{message_id}")
async def delete_message(
    message_id: int, db: Session = Depends(get_db), _admin: User = Depends(require_admin)
) -> dict:
    msg = db.get(ChatMessage, message_id)
    if msg is None:
        raise HTTPException(status_code=404, detail="Nachricht nicht gefunden")
    db.delete(msg)
    db.commit()
    return {"success": True}
