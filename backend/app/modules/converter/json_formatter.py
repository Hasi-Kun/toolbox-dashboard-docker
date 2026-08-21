"""JSON-Formatter -- validiert und formatiert JSON nach RFC 8259
(einheitliche Einrueckung, sortierbare/lesbare Ausgabe) oder komprimiert
es (minified, ein Einzeiler ohne unnoetige Leerzeichen).
"""

import json

from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module

_MAX_INPUT_LENGTH = 2_000_000  # ~2 MB Text -- Sicherheitsgrenze gegen extrem grosse Eingaben


@register_module
class JsonFormatterModule(ToolModule):
    slug = "json-formatter"
    category = "converter"
    name = "JSON-Formatter"
    description = (
        "Validiert JSON nach RFC 8259 und formatiert es lesbar (einheitliche Einrueckung) oder "
        "kompakt (minified, ein Einzeiler). Zeigt bei ungueltigem JSON die genaue Fehlerstelle."
    )
    is_active_scan = False
    timeout_seconds = 8

    class Input(BaseModel):
        json_text: str
        indent: int = 2
        sort_keys: bool = False
        mode: str = "pretty"  # "pretty" | "minify"

        @field_validator("json_text")
        @classmethod
        def validate_json_text(cls, v: str) -> str:
            if not v.strip():
                raise ValueError("Eingabe darf nicht leer sein")
            if len(v) > _MAX_INPUT_LENGTH:
                raise ValueError("Eingabe zu gross (max. 2 MB)")
            return v

        @field_validator("indent")
        @classmethod
        def validate_indent(cls, v: int) -> int:
            return max(0, min(v, 8))

        @field_validator("mode")
        @classmethod
        def validate_mode(cls, v: str) -> str:
            if v not in ("pretty", "minify"):
                raise ValueError("mode muss 'pretty' oder 'minify' sein")
            return v

    class Output(BaseModel):
        valid: bool
        formatted: str | None = None
        error: str | None = None
        error_line: int | None = None
        error_column: int | None = None
        size_bytes: int | None = None
        key_count: int | None = None

    async def run(self, data: Input) -> Output:
        try:
            parsed = json.loads(data.json_text)
        except json.JSONDecodeError as exc:
            return self.Output(
                valid=False,
                error=exc.msg,
                error_line=exc.lineno,
                error_column=exc.colno,
            )

        if data.mode == "minify":
            formatted = json.dumps(parsed, separators=(",", ":"), sort_keys=data.sort_keys, ensure_ascii=False)
        else:
            formatted = json.dumps(parsed, indent=data.indent, sort_keys=data.sort_keys, ensure_ascii=False)

        return self.Output(
            valid=True,
            formatted=formatted,
            size_bytes=len(formatted.encode("utf-8")),
            key_count=_count_keys(parsed),
        )


def _count_keys(value, _seen=None) -> int:
    """Rekursive Zaehlung aller Objekt-Schluessel (nur zur informativen
    Anzeige, z.B. 'enthaelt 42 Schluessel') -- mit Zyklenschutz, obwohl
    json.loads() selbst keine zyklischen Strukturen erzeugen kann."""
    if _seen is None:
        _seen = set()
    obj_id = id(value)
    if obj_id in _seen:
        return 0
    _seen.add(obj_id)

    if isinstance(value, dict):
        return len(value) + sum(_count_keys(v, _seen) for v in value.values())
    if isinstance(value, list):
        return sum(_count_keys(v, _seen) for v in value)
    return 0
