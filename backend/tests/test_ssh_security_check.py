"""Tests fuer den SSH-Sicherheitscheck. Die Kernlogik (Banner-Grab,
Host-Key-Algorithmus- und Auth-Methoden-Erkennung ueber den
password_auth_requested-Callback) wurde zusaetzlich live gegen einen
echten lokalen sshd verifiziert -- hier folgen die gemockten Tests fuer
die CI-Suite.
"""

from unittest.mock import AsyncMock, patch

import pytest
from pydantic import ValidationError

import asyncssh


def test_ssh_security_check_registered():
    from app.modules import get_registry

    assert "ssh-security-check" in get_registry()


def test_ssh_security_check_rejects_invalid_host():
    from app.modules.security.ssh_security_check import SshSecurityCheckModule

    with pytest.raises(ValidationError):
        SshSecurityCheckModule.Input(host="not a host; rm -rf /")


def test_ssh_security_check_rejects_invalid_port():
    from app.modules.security.ssh_security_check import SshSecurityCheckModule

    with pytest.raises(ValidationError):
        SshSecurityCheckModule.Input(host="example.com", port=99999)


@pytest.mark.asyncio
async def test_no_banner_reports_clean_failure():
    from app.modules.security.ssh_security_check import SshSecurityCheckModule

    with patch("app.modules.security.ssh_security_check._grab_banner", new=AsyncMock(return_value=None)):
        result = await SshSecurityCheckModule().run(SshSecurityCheckModule.Input(host="example.com"))

    assert result.success is False
    assert "Banner" in result.error


@pytest.mark.asyncio
async def test_weak_host_key_is_flagged():
    from app.modules.security.ssh_security_check import SshSecurityCheckModule

    class FakeHostKey:
        def get_algorithm(self):
            return "ssh-rsa"

    class FakeConn:
        def get_server_host_key(self):
            return FakeHostKey()

        def close(self):
            pass

    class FakeConnectCM:
        def __init__(self, client_factory, **kwargs):
            self.client_factory = client_factory

        async def __aenter__(self):
            client = self.client_factory()
            client.conn = FakeConn()
            client.auth_methods = ["password"]
            raise asyncssh.PermissionDenied("denied")

        async def __aexit__(self, *args):
            return False

    def fake_connect(*args, **kwargs):
        return FakeConnectCM(**kwargs)

    with patch("app.modules.security.ssh_security_check._grab_banner", new=AsyncMock(return_value="SSH-2.0-OpenSSH_9.6")), \
         patch("asyncssh.connect", new=fake_connect):
        result = await SshSecurityCheckModule().run(SshSecurityCheckModule.Input(host="example.com"))

    assert result.success is True
    assert result.host_key_algorithm == "ssh-rsa"
    assert any("veraltet" in w for w in result.warnings)
    assert any("Passwort" in w for w in result.warnings)


@pytest.mark.asyncio
async def test_modern_host_key_not_flagged():
    from app.modules.security.ssh_security_check import SshSecurityCheckModule

    class FakeHostKey:
        def get_algorithm(self):
            return "ssh-ed25519"

    class FakeConn:
        def get_server_host_key(self):
            return FakeHostKey()

        def close(self):
            pass

    class FakeConnectCM:
        def __init__(self, client_factory, **kwargs):
            self.client_factory = client_factory

        async def __aenter__(self):
            client = self.client_factory()
            client.conn = FakeConn()
            client.auth_methods = ["publickey"]
            raise asyncssh.PermissionDenied("denied")

        async def __aexit__(self, *args):
            return False

    def fake_connect(*args, **kwargs):
        return FakeConnectCM(**kwargs)

    with patch("app.modules.security.ssh_security_check._grab_banner", new=AsyncMock(return_value="SSH-2.0-OpenSSH_9.6")), \
         patch("asyncssh.connect", new=fake_connect):
        result = await SshSecurityCheckModule().run(SshSecurityCheckModule.Input(host="example.com"))

    assert result.host_key_algorithm == "ssh-ed25519"
    assert not any("veraltet" in w for w in result.warnings)
    assert not any("Passwort" in w for w in result.warnings)
