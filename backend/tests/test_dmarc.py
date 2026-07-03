from app.modules.mail.dmarc import DmarcCheckModule


def test_parses_reject_policy():
    raw = "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
    result = DmarcCheckModule._parse_record("example.com", raw, extra_warnings=[])

    assert result.policy == "reject"
    assert result.percentage == 100
    assert result.aggregate_reports == ["mailto:dmarc@example.com"]
    assert not any("none" in w for w in result.warnings)


def test_warns_on_none_policy():
    raw = "v=DMARC1; p=none"
    result = DmarcCheckModule._parse_record("example.com", raw, extra_warnings=[])

    assert result.policy == "none"
    assert any("none" in w for w in result.warnings)


def test_subdomain_policy_falls_back_to_main_policy():
    raw = "v=DMARC1; p=quarantine"
    result = DmarcCheckModule._parse_record("example.com", raw, extra_warnings=[])

    assert result.subdomain_policy == "quarantine"


def test_parses_multiple_report_addresses():
    raw = "v=DMARC1; p=reject; rua=mailto:a@example.com,mailto:b@example.com"
    result = DmarcCheckModule._parse_record("example.com", raw, extra_warnings=[])

    assert result.aggregate_reports == ["mailto:a@example.com", "mailto:b@example.com"]


def test_warns_on_partial_percentage():
    raw = "v=DMARC1; p=reject; pct=50"
    result = DmarcCheckModule._parse_record("example.com", raw, extra_warnings=[])

    assert result.percentage == 50
    assert any("50%" in w for w in result.warnings)
