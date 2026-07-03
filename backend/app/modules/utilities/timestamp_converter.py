from datetime import datetime, timezone

from pydantic import BaseModel

from app.modules.base import ToolModule, register_module


@register_module
class TimestampConverterModule(ToolModule):
    slug = "timestamp-converter"
    category = "utilities"
    name = "Timestamp Konverter"
    description = "Konvertiert zwischen Unix-Timestamp und ISO-8601-Datum (Eingabeformat wird automatisch erkannt)."
    is_active_scan = False
    timeout_seconds = 5

    class Input(BaseModel):
        value: str

    class Output(BaseModel):
        input: str
        unix_timestamp: int | None
        iso_utc: str | None
        human_readable_utc: str | None
        error: str | None

    async def run(self, data: Input) -> Output:
        raw = data.value.strip()

        dt: datetime | None = None
        if raw.lstrip("-").isdigit():
            try:
                dt = datetime.fromtimestamp(int(raw), tz=timezone.utc)
            except (ValueError, OSError, OverflowError) as exc:
                return self.Output(input=raw, unix_timestamp=None, iso_utc=None, human_readable_utc=None, error=str(exc))
        else:
            try:
                normalized = raw.replace("Z", "+00:00")
                dt = datetime.fromisoformat(normalized)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
            except ValueError as exc:
                return self.Output(
                    input=raw, unix_timestamp=None, iso_utc=None, human_readable_utc=None,
                    error=f"Konnte nicht als Unix-Timestamp oder ISO-8601-Datum interpretiert werden: {exc}",
                )

        return self.Output(
            input=raw,
            unix_timestamp=int(dt.timestamp()),
            iso_utc=dt.astimezone(timezone.utc).isoformat(),
            human_readable_utc=dt.astimezone(timezone.utc).strftime("%A, %d %B %Y %H:%M:%S UTC"),
            error=None,
        )
