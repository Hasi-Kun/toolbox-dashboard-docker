import hashlib

from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module

ALLOWED_ALGORITHMS = {"md5", "sha1", "sha256", "sha512"}


@register_module
class HashGeneratorModule(ToolModule):
    slug = "hash-generator"
    category = "utilities"
    name = "Hash Generator"
    description = "Berechnet MD5/SHA1/SHA256/SHA512-Hashes eines Texts."
    is_active_scan = False
    timeout_seconds = 5

    class Input(BaseModel):
        text: str
        algorithms: list[str] = ["md5", "sha1", "sha256", "sha512"]

        @field_validator("algorithms")
        @classmethod
        def validate_algorithms(cls, v: list[str]) -> list[str]:
            v = [a.lower() for a in v]
            invalid = set(v) - ALLOWED_ALGORITHMS
            if invalid:
                raise ValueError(f"Nicht unterstuetzte Algorithmen: {sorted(invalid)}")
            if not v:
                raise ValueError("Mindestens ein Algorithmus erforderlich")
            return v

    class Output(BaseModel):
        text: str
        hashes: dict[str, str]

    async def run(self, data: Input) -> Output:
        encoded = data.text.encode("utf-8")
        hashes = {algo: hashlib.new(algo, encoded).hexdigest() for algo in data.algorithms}
        return self.Output(text=data.text, hashes=hashes)
