import re

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from app.api.deps import require_admin
from app.core.db import get_db
from app.models.user import AppearanceSettings, User

router = APIRouter()

ALLOWED_STYLES = {"none", "dots", "gradient", "starfield", "custom"}
HEX_COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")


class AppearanceOut(BaseModel):
    background_style: str
    custom_background_url: str | None
    animation_speed: float
    gradient_color: str
    interactive_dots: bool
    form_opacity_percent: int
    form_blur_px: int

    model_config = {"from_attributes": True}


class UpdateAppearanceRequest(BaseModel):
    background_style: str
    custom_background_url: str | None = None
    animation_speed: float = 1.0
    gradient_color: str = "#35E0C0"
    interactive_dots: bool = True
    form_opacity_percent: int = 90
    form_blur_px: int = 4

    @field_validator("background_style")
    @classmethod
    def validate_style(cls, v: str) -> str:
        if v not in ALLOWED_STYLES:
            raise ValueError(f"Ungueltiger Stil, erlaubt: {sorted(ALLOWED_STYLES)}")
        return v

    @field_validator("custom_background_url")
    @classmethod
    def validate_url(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.strip()
        if not v:
            return None
        if not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("URL muss mit http:// oder https:// beginnen")
        if len(v) > 500:
            raise ValueError("URL zu lang")
        return v

    @field_validator("animation_speed")
    @classmethod
    def validate_speed(cls, v: float) -> float:
        return max(0.25, min(v, 3.0))

    @field_validator("gradient_color")
    @classmethod
    def validate_color(cls, v: str) -> str:
        v = v.strip()
        if not HEX_COLOR_RE.match(v):
            raise ValueError("Farbe muss ein Hex-Code sein, z.B. #35E0C0")
        return v

    @field_validator("form_opacity_percent")
    @classmethod
    def validate_opacity(cls, v: int) -> int:
        return max(0, min(v, 100))

    @field_validator("form_blur_px")
    @classmethod
    def validate_blur(cls, v: int) -> int:
        return max(0, min(v, 20))


def _get_or_create(db: Session) -> AppearanceSettings:
    settings = db.get(AppearanceSettings, 1)
    if settings is None:
        settings = AppearanceSettings(id=1, background_style="dots", custom_background_url=None)
        db.add(settings)
        db.commit()
        db.refresh(settings)
    return settings


@router.get("/appearance", response_model=AppearanceOut)
async def get_appearance(db: Session = Depends(get_db)) -> AppearanceSettings:
    """Bewusst OHNE Auth -- die Login-Seite muss den Hintergrund rendern
    koennen, bevor irgendjemand eingeloggt ist."""
    return _get_or_create(db)


@router.patch("/appearance", response_model=AppearanceOut)
async def update_appearance(
    payload: UpdateAppearanceRequest, db: Session = Depends(get_db), _admin: User = Depends(require_admin)
) -> AppearanceSettings:
    if payload.background_style == "custom" and not payload.custom_background_url:
        raise HTTPException(status_code=400, detail="Fuer 'custom' wird eine Hintergrundbild-URL benoetigt")

    settings = _get_or_create(db)
    settings.background_style = payload.background_style
    settings.custom_background_url = payload.custom_background_url if payload.background_style == "custom" else None
    settings.animation_speed = payload.animation_speed
    settings.gradient_color = payload.gradient_color
    settings.interactive_dots = payload.interactive_dots
    settings.form_opacity_percent = payload.form_opacity_percent
    settings.form_blur_px = payload.form_blur_px
    db.add(settings)
    db.commit()
    db.refresh(settings)
    return settings
