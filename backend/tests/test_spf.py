from app.modules.mail.spf import SpfCheckModule


def test_parses_basic_mechanisms():
    raw = "v=spf1 ip4:203.0.113.0/24 include:_spf.example.com -all"
    mechanisms = SpfCheckModule._parse(raw)

    assert [m.mechanism for m in mechanisms] == ["ip4", "include", "all"]
    assert mechanisms[0].value == "203.0.113.0/24"
    assert mechanisms[1].value == "_spf.example.com"
    assert mechanisms[2].qualifier == "-"


def test_parses_qualifiers_correctly():
    raw = "v=spf1 +a ~mx ?exists:%{i}._spoof.example.com -all"
    mechanisms = SpfCheckModule._parse(raw)

    assert mechanisms[0].qualifier == "+"
    assert mechanisms[0].mechanism == "a"
    assert mechanisms[1].qualifier == "~"
    assert mechanisms[1].mechanism == "mx"
    assert mechanisms[2].qualifier == "?"
    assert mechanisms[2].mechanism == "exists"


def test_parses_redirect_modifier():
    raw = "v=spf1 redirect=_spf.example.com"
    mechanisms = SpfCheckModule._parse(raw)

    assert mechanisms[0].mechanism == "redirect"
    assert mechanisms[0].value == "_spf.example.com"


def test_default_qualifier_is_plus():
    raw = "v=spf1 a mx all"
    mechanisms = SpfCheckModule._parse(raw)

    assert all(m.qualifier == "+" for m in mechanisms)
