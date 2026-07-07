import csv
import io

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, field_validator
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_admin
from app.core.db import get_db
from app.core.rate_limit import enforce_rate_limit
from app.models.user import (
    FeatureRequest,
    FeatureRequestComment,
    FeatureRequestStatus,
    FeatureRequestVote,
    User,
)

router = APIRouter(prefix="/feature-requests", tags=["feature-requests"])

ALLOWED_STATUSES = {s.value for s in FeatureRequestStatus}
# Vorgefertigte, feste Tag-Auswahl -- bewusst keine Freitext-Tags, damit
# die Filterung auf der Liste immer eine ueberschaubare, konsistente
# Menge an Werten hat.
ALLOWED_TAGS = ["tools", "dashboard", "ui", "security", "performance", "other"]


class CreateRequestPayload(BaseModel):
    title: str
    description: str
    tags: list[str] = []

    @field_validator("title")
    @classmethod
    def validate_title(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) > 150:
            raise ValueError("Titel muss 1-150 Zeichen haben")
        return v

    @field_validator("description")
    @classmethod
    def validate_description(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) > 3000:
            raise ValueError("Beschreibung muss 1-3000 Zeichen haben")
        return v

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, v: list[str]) -> list[str]:
        v = [t.strip().lower() for t in v if t.strip()]
        unknown = set(v) - set(ALLOWED_TAGS)
        if unknown:
            raise ValueError(f"Unbekannte Tags: {sorted(unknown)}, erlaubt: {ALLOWED_TAGS}")
        if len(v) > 5:
            raise ValueError("Maximal 5 Tags pro Vorschlag")
        return sorted(set(v))


class CommentPayload(BaseModel):
    comment: str

    @field_validator("comment")
    @classmethod
    def validate_comment(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) > 1000:
            raise ValueError("Kommentar muss 1-1000 Zeichen haben")
        return v


class UpdateStatusPayload(BaseModel):
    status: str

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: str) -> str:
        if v not in ALLOWED_STATUSES:
            raise ValueError(f"Ungueltiger Status, erlaubt: {sorted(ALLOWED_STATUSES)}")
        return v


class VotePayload(BaseModel):
    direction: str

    @field_validator("direction")
    @classmethod
    def validate_direction(cls, v: str) -> str:
        if v not in ("up", "down"):
            raise ValueError("direction muss 'up' oder 'down' sein")
        return v


class RequestSummaryOut(BaseModel):
    id: int
    title: str
    description: str
    status: str
    username: str
    created_at: str
    score: int
    upvotes: int
    downvotes: int
    comment_count: int
    user_vote: int
    role: str = "member"
    is_premium: bool = False
    premium_badge_color: str = "#F5C518"
    display_name_style: str = "default"
    display_name_color: str = "#35E0C0"
    display_name_gradient_color: str = "#F5C518"
    tags: list[str] = []


class CommentOut(BaseModel):
    id: int
    username: str
    comment: str
    created_at: str
    role: str = "member"
    is_premium: bool = False
    premium_badge_color: str = "#F5C518"
    display_name_style: str = "default"
    display_name_color: str = "#35E0C0"
    display_name_gradient_color: str = "#F5C518"


class RequestDetailOut(RequestSummaryOut):
    comments: list[CommentOut]


def _author_fields(author: User | None) -> dict:
    if author is None:
        return {}
    return {
        "role": author.role,
        "is_premium": author.is_premium,
        "premium_badge_color": author.premium_badge_color,
        "display_name_style": author.display_name_style,
        "display_name_color": author.display_name_color,
        "display_name_gradient_color": author.display_name_gradient_color,
    }


def _score(db: Session, request_id: int) -> int:
    return db.query(func.coalesce(func.sum(FeatureRequestVote.vote_value), 0)).filter(
        FeatureRequestVote.request_id == request_id
    ).scalar() or 0


def _upvotes(db: Session, request_id: int) -> int:
    return db.query(func.count(FeatureRequestVote.id)).filter(
        FeatureRequestVote.request_id == request_id, FeatureRequestVote.vote_value == 1
    ).scalar() or 0


def _downvotes(db: Session, request_id: int) -> int:
    return db.query(func.count(FeatureRequestVote.id)).filter(
        FeatureRequestVote.request_id == request_id, FeatureRequestVote.vote_value == -1
    ).scalar() or 0


def _user_vote(db: Session, request_id: int, user_id: int) -> int:
    vote = (
        db.query(FeatureRequestVote)
        .filter(FeatureRequestVote.request_id == request_id, FeatureRequestVote.user_id == user_id)
        .first()
    )
    return vote.vote_value if vote else 0


def _summary(db: Session, fr: FeatureRequest, user_id: int) -> RequestSummaryOut:
    author = db.get(User, fr.user_id) if fr.user_id else None
    return RequestSummaryOut(
        id=fr.id, title=fr.title, description=fr.description, status=fr.status, username=fr.username,
        created_at=fr.created_at.isoformat(), score=_score(db, fr.id),
        upvotes=_upvotes(db, fr.id), downvotes=_downvotes(db, fr.id),
        comment_count=len(fr.comments), user_vote=_user_vote(db, fr.id, user_id),
        tags=[t for t in fr.tags.split(",") if t],
        **_author_fields(author),
    )


class PaginatedRequestsOut(BaseModel):
    items: list[RequestSummaryOut]
    total: int
    page: int
    page_size: int
    total_pages: int


@router.get("", response_model=PaginatedRequestsOut)
async def list_requests(
    search: str | None = None,
    tag: str | None = None,
    page: int = 1,
    page_size: int = 25,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> PaginatedRequestsOut:
    page = max(1, page)
    page_size = max(1, min(page_size, 100))

    requests = db.query(FeatureRequest).all()
    summaries = [_summary(db, r, user.id) for r in requests]

    if search:
        needle = search.strip().lower()
        summaries = [s for s in summaries if needle in s.title.lower() or needle in s.description.lower()]
    if tag:
        summaries = [s for s in summaries if tag.lower() in s.tags]

    # Hoechster Score zuerst, bei Gleichstand neueste zuerst
    summaries.sort(key=lambda s: s.created_at, reverse=True)
    summaries.sort(key=lambda s: s.score, reverse=True)

    total = len(summaries)
    total_pages = max(1, (total + page_size - 1) // page_size)
    page = min(page, total_pages)
    start = (page - 1) * page_size
    page_items = summaries[start : start + page_size]

    return PaginatedRequestsOut(items=page_items, total=total, page=page, page_size=page_size, total_pages=total_pages)


@router.post("", response_model=RequestSummaryOut)
async def create_request(
    payload: CreateRequestPayload, request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)
) -> RequestSummaryOut:
    await enforce_rate_limit(request, bucket="feature-request-create", limit=10)

    fr = FeatureRequest(
        user_id=user.id, username=user.username, title=payload.title, description=payload.description,
        tags=",".join(payload.tags),
    )
    db.add(fr)
    db.commit()
    db.refresh(fr)
    return _summary(db, fr, user.id)


@router.get("/tags")
async def list_available_tags(_user: User = Depends(get_current_user)) -> list[str]:
    return ALLOWED_TAGS


@router.get("/export.csv")
async def export_csv(db: Session = Depends(get_db), _user: User = Depends(get_current_user)) -> StreamingResponse:
    """CSV-Export der kompletten Liste fuer die Weiterverarbeitung
    (Tabellenkalkulation, Reporting, etc)."""
    requests = db.query(FeatureRequest).order_by(FeatureRequest.created_at.desc()).all()

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["id", "title", "description", "status", "username", "created_at", "score", "upvotes", "downvotes", "comment_count"])
    for r in requests:
        writer.writerow([
            r.id, r.title, r.description, r.status, r.username, r.created_at.isoformat(),
            _score(db, r.id), _upvotes(db, r.id), _downvotes(db, r.id), len(r.comments),
        ])

    buffer.seek(0)
    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=feature-requests.csv"},
    )


@router.get("/{request_id}", response_model=RequestDetailOut)
async def get_request(request_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> RequestDetailOut:
    fr = db.get(FeatureRequest, request_id)
    if fr is None:
        raise HTTPException(status_code=404, detail="Feature-Request nicht gefunden")

    comments = sorted(fr.comments, key=lambda c: c.created_at)
    commenter_ids = {c.user_id for c in comments if c.user_id is not None}
    commenters = {u.id: u for u in db.query(User).filter(User.id.in_(commenter_ids)).all()} if commenter_ids else {}

    summary = _summary(db, fr, user.id)
    return RequestDetailOut(
        **summary.model_dump(),
        comments=[
            CommentOut(
                id=c.id, username=c.username, comment=c.comment, created_at=c.created_at.isoformat(),
                **_author_fields(commenters.get(c.user_id)),
            )
            for c in comments
        ],
    )


@router.post("/{request_id}/vote")
async def cast_vote(request_id: int, payload: VotePayload, db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> dict:
    fr = db.get(FeatureRequest, request_id)
    if fr is None:
        raise HTTPException(status_code=404, detail="Feature-Request nicht gefunden")

    new_value = 1 if payload.direction == "up" else -1
    existing = (
        db.query(FeatureRequestVote)
        .filter(FeatureRequestVote.request_id == request_id, FeatureRequestVote.user_id == user.id)
        .first()
    )

    if existing and existing.vote_value == new_value:
        db.delete(existing)
        db.commit()
        user_vote = 0
    elif existing:
        existing.vote_value = new_value
        db.add(existing)
        db.commit()
        user_vote = new_value
    else:
        db.add(FeatureRequestVote(request_id=request_id, user_id=user.id, vote_value=new_value))
        db.commit()
        user_vote = new_value

    return {"user_vote": user_vote, "score": _score(db, request_id), "upvotes": _upvotes(db, request_id), "downvotes": _downvotes(db, request_id)}


@router.post("/{request_id}/comments", response_model=CommentOut)
async def add_comment(
    request_id: int, payload: CommentPayload, request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)
) -> CommentOut:
    await enforce_rate_limit(request, bucket="feature-request-comment", limit=20)

    fr = db.get(FeatureRequest, request_id)
    if fr is None:
        raise HTTPException(status_code=404, detail="Feature-Request nicht gefunden")

    comment = FeatureRequestComment(request_id=request_id, user_id=user.id, username=user.username, comment=payload.comment)
    db.add(comment)
    db.commit()
    db.refresh(comment)
    return CommentOut(
        id=comment.id, username=comment.username, comment=comment.comment, created_at=comment.created_at.isoformat(),
        **_author_fields(user),
    )


@router.delete("/{request_id}/comments/{comment_id}")
async def delete_comment(
    request_id: int, comment_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)
) -> dict:
    comment = db.get(FeatureRequestComment, comment_id)
    if comment is None or comment.request_id != request_id:
        raise HTTPException(status_code=404, detail="Kommentar nicht gefunden")
    if comment.user_id != user.id and user.role != "admin":
        raise HTTPException(status_code=403, detail="Nur eigene Kommentare oder als Admin loeschbar")
    db.delete(comment)
    db.commit()
    return {"success": True}


@router.patch("/{request_id}/status", response_model=RequestSummaryOut)
async def update_status(
    request_id: int, payload: UpdateStatusPayload, db: Session = Depends(get_db), admin: User = Depends(require_admin)
) -> RequestSummaryOut:
    fr = db.get(FeatureRequest, request_id)
    if fr is None:
        raise HTTPException(status_code=404, detail="Feature-Request nicht gefunden")

    fr.status = payload.status
    db.add(fr)
    db.commit()
    db.refresh(fr)
    return _summary(db, fr, admin.id)


@router.delete("/{request_id}")
async def delete_request(request_id: int, db: Session = Depends(get_db), _admin: User = Depends(require_admin)) -> dict:
    fr = db.get(FeatureRequest, request_id)
    if fr is None:
        raise HTTPException(status_code=404, detail="Feature-Request nicht gefunden")
    db.delete(fr)
    db.commit()
    return {"success": True}
