import base64
import binascii
from typing import Literal

from pydantic import BaseModel

from app.modules.base import ToolModule, register_module


@register_module
class Base64ToolModule(ToolModule):
    slug = "base64-tool"
    category = "utilities"
    name = "Base64 Encode/Decode"
    description = "Kodiert oder dekodiert Text als Base64."
    is_active_scan = False
    timeout_seconds = 5

    class Input(BaseModel):
        text: str
        operation: Literal["encode", "decode"] = "encode"

    class Output(BaseModel):
        input: str
        operation: str
        result: str | None
        error: str | None

    async def run(self, data: Input) -> Output:
        try:
            if data.operation == "encode":
                result = base64.b64encode(data.text.encode("utf-8")).decode("ascii")
            else:
                result = base64.b64decode(data.text, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError) as exc:
            return self.Output(input=data.text, operation=data.operation, result=None, error=str(exc))

        return self.Output(input=data.text, operation=data.operation, result=result, error=None)
