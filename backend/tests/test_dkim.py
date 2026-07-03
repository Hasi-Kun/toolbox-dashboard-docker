from app.modules.mail.dkim import DkimCheckModule


def test_parses_rsa_key_present():
    raw = "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GN..."
    result = DkimCheckModule._parse_record("default", raw)

    assert result.found is True
    assert result.key_type == "rsa"
    assert result.public_key_present is True


def test_defaults_key_type_to_rsa_when_missing():
    raw = "v=DKIM1; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GN..."
    result = DkimCheckModule._parse_record("google", raw)

    assert result.key_type == "rsa"


def test_detects_empty_public_key_as_revoked():
    # Ein leerer p= Tag bedeutet: Selector wurde widerrufen (RFC 6376).
    raw = "v=DKIM1; k=rsa; p="
    result = DkimCheckModule._parse_record("selector1", raw)

    assert result.public_key_present is False
