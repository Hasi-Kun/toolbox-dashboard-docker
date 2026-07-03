import uuid
from typing import Literal

from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module


@register_module
class UuidGeneratorModule(ToolModule):
    slug = "uuid-generator"
    category = "utilities"
    name = "UUID Generator"
    description = "Generiert UUIDs (Version 1 oder 4)."
    is_active_scan = False
    timeout_seconds = 5

    class Input(BaseModel):
        version: Literal[1, 4] = 4
        count: int = 1

        @field_validator("count")
        @classmethod
        def validate_count(cls, v: int) -> int:
            return max(1, min(v, 50))

    class Output(BaseModel):
        version: int
        uuids: list[str]

    async def run(self, data: Input) -> Output:
        generator = uuid.uuid1 if data.version == 1 else uuid.uuid4
        uuids = [str(generator()) for _ in range(data.count)]
        return self.Output(version=data.version, uuids=uuids)
