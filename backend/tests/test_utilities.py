"""Tests fuer die Utilities-Kategorie. Alle Module wurden vorab manuell
gegen unabhaengig berechnete Referenzwerte verifiziert (siehe Kommentare);
hier als pytest fuer die Regressions-Suite.
"""

import hashlib
import uuid as uuid_module

import pytest
from pydantic import ValidationError

from app.modules.utilities.base64_tool import Base64ToolModule
from app.modules.utilities.cidr_calculator import CidrCalculatorModule
from app.modules.utilities.hash_generator import HashGeneratorModule
from app.modules.utilities.jwt_decoder import JwtDecoderModule
from app.modules.utilities.password_generator import PasswordGeneratorModule
from app.modules.utilities.timestamp_converter import TimestampConverterModule
from app.modules.utilities.uuid_generator import UuidGeneratorModule


@pytest.mark.asyncio
async def test_hash_generator_matches_stdlib():
    result = await HashGeneratorModule().run(HashGeneratorModule.Input(text="hello"))
    assert result.hashes["md5"] == hashlib.md5(b"hello").hexdigest()
    assert result.hashes["sha256"] == hashlib.sha256(b"hello").hexdigest()


def test_hash_generator_rejects_unknown_algorithm():
    with pytest.raises(ValidationError):
        HashGeneratorModule.Input(text="hello", algorithms=["md5", "sha3000"])


@pytest.mark.asyncio
async def test_base64_round_trip():
    encoded = await Base64ToolModule().run(Base64ToolModule.Input(text="Hallo Welt!", operation="encode"))
    assert encoded.result == "SGFsbG8gV2VsdCE="

    decoded = await Base64ToolModule().run(Base64ToolModule.Input(text=encoded.result, operation="decode"))
    assert decoded.result == "Hallo Welt!"


@pytest.mark.asyncio
async def test_base64_invalid_input_returns_clean_error():
    result = await Base64ToolModule().run(Base64ToolModule.Input(text="!!!not base64!!!", operation="decode"))
    assert result.result is None
    assert result.error is not None


@pytest.mark.asyncio
async def test_jwt_decoder_verifies_correct_and_incorrect_signature():
    import base64
    import hmac
    import json

    def b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": "123", "name": "Test"}
    secret = "test-secret"
    signing_input = f"{b64url(json.dumps(header).encode())}.{b64url(json.dumps(payload).encode())}"
    sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    token = f"{signing_input}.{b64url(sig)}"

    correct = await JwtDecoderModule().run(JwtDecoderModule.Input(token=token, secret=secret))
    assert correct.valid_format is True
    assert correct.payload["name"] == "Test"
    assert correct.signature_valid is True

    wrong = await JwtDecoderModule().run(JwtDecoderModule.Input(token=token, secret="wrong-secret"))
    assert wrong.signature_valid is False


@pytest.mark.asyncio
async def test_jwt_decoder_rejects_malformed_token():
    result = await JwtDecoderModule().run(JwtDecoderModule.Input(token="not-a-jwt"))
    assert result.valid_format is False


@pytest.mark.asyncio
async def test_uuid_generator_produces_unique_valid_uuids():
    result = await UuidGeneratorModule().run(UuidGeneratorModule.Input(version=4, count=10))
    assert len(result.uuids) == 10
    assert len(set(result.uuids)) == 10
    for u in result.uuids:
        assert uuid_module.UUID(u).version == 4


def test_uuid_generator_count_is_clamped():
    assert UuidGeneratorModule.Input(count=0).count == 1
    assert UuidGeneratorModule.Input(count=999).count == 50


@pytest.mark.asyncio
async def test_password_generator_produces_correct_length_and_uniqueness():
    result = await PasswordGeneratorModule().run(PasswordGeneratorModule.Input(length=20, count=5))
    assert len(result.passwords) == 5
    assert all(len(p) == 20 for p in result.passwords)
    assert len(set(result.passwords)) == 5


def test_password_generator_requires_at_least_one_charset():
    with pytest.raises(ValidationError):
        PasswordGeneratorModule.Input(use_uppercase=False, use_lowercase=False, use_digits=False, use_symbols=False)


@pytest.mark.asyncio
async def test_cidr_calculator_matches_known_reference_values():
    result = await CidrCalculatorModule().run(CidrCalculatorModule.Input(cidr="192.168.1.0/24"))
    assert result.network_address == "192.168.1.0"
    assert result.broadcast_address == "192.168.1.255"
    assert result.first_usable == "192.168.1.1"
    assert result.last_usable == "192.168.1.254"
    assert result.usable_addresses == 254
    assert result.is_private is True


def test_cidr_calculator_rejects_invalid_cidr():
    with pytest.raises(ValidationError):
        CidrCalculatorModule.Input(cidr="not-a-cidr")


@pytest.mark.asyncio
async def test_timestamp_converter_round_trip():
    from_unix = await TimestampConverterModule().run(TimestampConverterModule.Input(value="1700000000"))
    assert from_unix.unix_timestamp == 1700000000

    from_iso = await TimestampConverterModule().run(TimestampConverterModule.Input(value=from_unix.iso_utc))
    assert from_iso.unix_timestamp == 1700000000


@pytest.mark.asyncio
async def test_timestamp_converter_rejects_garbage_input():
    result = await TimestampConverterModule().run(TimestampConverterModule.Input(value="definitely not a date"))
    assert result.error is not None
