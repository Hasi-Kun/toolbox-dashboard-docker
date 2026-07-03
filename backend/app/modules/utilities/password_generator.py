import math
import secrets
import string

from pydantic import BaseModel, field_validator, model_validator

from app.modules.base import ToolModule, register_module


@register_module
class PasswordGeneratorModule(ToolModule):
    slug = "password-generator"
    category = "utilities"
    name = "Passwort Generator"
    description = "Generiert kryptografisch sichere zufaellige Passwoerter."
    is_active_scan = False
    timeout_seconds = 5

    class Input(BaseModel):
        length: int = 16
        use_uppercase: bool = True
        use_lowercase: bool = True
        use_digits: bool = True
        use_symbols: bool = True
        count: int = 1

        @field_validator("length")
        @classmethod
        def validate_length(cls, v: int) -> int:
            return max(8, min(v, 128))

        @field_validator("count")
        @classmethod
        def validate_count(cls, v: int) -> int:
            return max(1, min(v, 20))

        @model_validator(mode="after")
        def validate_at_least_one_charset(self) -> "PasswordGeneratorModule.Input":
            if not any([self.use_uppercase, self.use_lowercase, self.use_digits, self.use_symbols]):
                raise ValueError("Mindestens ein Zeichensatz muss aktiviert sein")
            return self

    class Output(BaseModel):
        passwords: list[str]
        entropy_bits: float

    async def run(self, data: Input) -> Output:
        charset = ""
        if data.use_lowercase:
            charset += string.ascii_lowercase
        if data.use_uppercase:
            charset += string.ascii_uppercase
        if data.use_digits:
            charset += string.digits
        if data.use_symbols:
            charset += "!@#$%^&*()-_=+[]{}"

        passwords = ["".join(secrets.choice(charset) for _ in range(data.length)) for _ in range(data.count)]
        entropy_bits = round(data.length * math.log2(len(charset)), 1)

        return self.Output(passwords=passwords, entropy_bits=entropy_bits)
