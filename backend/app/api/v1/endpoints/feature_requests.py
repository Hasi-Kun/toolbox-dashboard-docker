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


class CreateRequestPayload(BaseModel):
    title: str
    description: str

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


class RequestSummaryOut(BaseModel):
    id: int
    title: str
    description: str
    status: str
    username: str
    created_at: str
    vote_count: int
    comment_count: int
    has_voted: bool


class CommentOut(BaseModel):
    id: int
    username: str
    comment: str
    created_at: str


class RequestDetailOut(RequestSummaryOut):
    comments: list[CommentOut]


def _vote_count(db: Session, request_id: int) -> int:
    return db.query(func.count(FeatureRequestVote.id)).filter(FeatureRequestVote.request_id == request_id).scalar() or 0


def _has_voted(db: Session, request_id: int, user_id: int) -> bool:
    return (
        db.query(FeatureRequestVote)
        .filter(FeatureRequestVote.request_id == request_id, FeatureRequestVote.user_id == user_id)
        .first()
        is not None
    )


@router.get("", response_model=list[RequestSummaryOut])
async def list_requests(db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> list[RequestSummaryOut]:
    requests = db.query(FeatureRequest).all()
    summaries = [
        RequestSummaryOut(
            id=r.id, title=r.title, description=r.description, status=r.status, username=r.username,
            created_at=r.created_at.isoformat(), vote_count=_vote_count(db, r.id),
            comment_count=len(r.comments), has_voted=_has_voted(db, r.id, user.id),
        )
        for r in requests
    ]
    # Meiste Stimmen zuerst, bei Gleichstand neueste zuerst
    summaries.sort(key=lambda s: s.created_at, reverse=True)
    summaries.sort(key=lambda s: s.vote_count, reverse=True)
    return summaries


@router.post("", response_model=RequestSummaryOut)
async def create_request(
    payload: CreateRequestPayload, request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)
) -> RequestSummaryOut:
    await enforce_rate_limit(request, bucket="feature-request-create", limit=10)

    fr = FeatureRequest(user_id=user.id, username=user.username, title=payload.title, description=payload.description)
    db.add(fr)
    db.commit()
    db.refresh(fr)
    return RequestSummaryOut(
        id=fr.id, title=fr.title, description=fr.description, status=fr.status, username=fr.username,
        created_at=fr.created_at.isoformat(), vote_count=0, comment_count=0, has_voted=False,
    )


@router.get("/export.csv")
async def export_csv(db: Session = Depends(get_db), _user: User = Depends(get_current_user)) -> StreamingResponse:
    """CSV-Export der kompletten Liste fuer die Weiterverarbeitung
    (Tabellenkalkulation, Reporting, etc)."""
    requests = db.query(FeatureRequest).order_by(FeatureRequest.created_at.desc()).all()

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["id", "title", "description", "status", "username", "created_at", "vote_count", "comment_count"])
    for r in requests:
        writer.writerow([
            r.id, r.title, r.description, r.status, r.username, r.created_at.isoformat(),
            _vote_count(db, r.id), len(r.comments),
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
    return RequestDetailOut(
        id=fr.id, title=fr.title, description=fr.description, status=fr.status, username=fr.username,
        created_at=fr.created_at.isoformat(), vote_count=_vote_count(db, fr.id), comment_count=len(comments),
        has_voted=_has_voted(db, fr.id, user.id),
        comments=[CommentOut(id=c.id, username=c.username, comment=c.comment, created_at=c.created_at.isoformat()) for c in comments],
    )


@router.post("/{request_id}/vote")
async def toggle_vote(request_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> dict:
    fr = db.get(FeatureRequest, request_id)
    if fr is None:
        raise HTTPException(status_code=404, detail="Feature-Request nicht gefunden")

    existing = (
        db.query(FeatureRequestVote)
        .filter(FeatureRequestVote.request_id == request_id, FeatureRequestVote.user_id == user.id)
        .first()
    )
    if existing:
        db.delete(existing)
        db.commit()
        return {"voted": False, "vote_count": _vote_count(db, request_id)}

    db.add(FeatureRequestVote(request_id=request_id, user_id=user.id))
    db.commit()
    return {"voted": True, "vote_count": _vote_count(db, request_id)}


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
    return CommentOut(id=comment.id, username=comment.username, comment=comment.comment, created_at=comment.created_at.isoformat())


@router.delete("/{request_id}/comments/{comment_id}")
async def delete_comment(
    request_id: int, comment_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)
) -> dict:
    comment = db.get(FeatureRequestComment, comment_id)
    if comment is None or comment.request_id != request_id:
        raise HTTPException(status_code=404, detail="Kommentar nicht gefunden")
    # Eigene Kommentare darf jeder loeschen, fremde nur ein Admin
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
    return RequestSummaryOut(
        id=fr.id, title=fr.title, description=fr.description, status=fr.status, username=fr.username,
        created_at=fr.created_at.isoformat(), vote_count=_vote_count(db, fr.id), comment_count=len(fr.comments),
        has_voted=_has_voted(db, fr.id, admin.id),
    )


@router.delete("/{request_id}")
async def delete_request(request_id: int, db: Session = Depends(get_db), _admin: User = Depends(require_admin)) -> dict:
    fr = db.get(FeatureRequest, request_id)
    if fr is None:
        raise HTTPException(status_code=404, detail="Feature-Request nicht gefunden")
    db.delete(fr)
    db.commit()
    return {"success": True}
