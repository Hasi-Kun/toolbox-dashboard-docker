# Security Policy

## Reporting a Vulnerability

Please report security issues **privately**. **Do not open a public GitHub issue for security vulnerabilities.**

Please contact **[arschzersexer@hasikun.cc](mailto:arschzersexer@hasikun.cc)** with the following information:

* A clear description of the vulnerability.
* The potential impact.
* Steps to reproduce the issue (or a proof of concept).
* The Toolbox Dashboard version (release tag or commit hash).
* Relevant environment details (operating system, Docker version, browser, etc.).

You can expect an acknowledgement within a few days. Please allow a reasonable amount of time for the issue to be investigated and fixed before making any public disclosure.

---

## Supported Versions

Security updates are only provided for the latest stable release available on the **Releases** page.

Older releases may contain known vulnerabilities and are not guaranteed to receive fixes.

---

## Security Considerations

Toolbox Dashboard is designed as a **self-hosted** application.

The security of the deployment depends on the configuration of the hosting environment. It is recommended to:

* Keep the operating system up to date.
* Keep Docker and Docker Compose updated.
* Use HTTPS (recommended via Caddy).
* Restrict access to administrative interfaces.
* Protect secrets and environment variables.
* Regularly update to the latest Toolbox Dashboard release.

---

## Authentication

The application supports modern authentication technologies, including:

* WebAuthn / Passkeys
* TOTP-based Multi-Factor Authentication (MFA)

Authentication settings should be configured according to your organization's security requirements.

---

## Backups

The built-in backup functionality should not be considered a complete disaster recovery solution.

For production environments, an independent backup strategy is strongly recommended. Regular **off-site backups** should be used to ensure recovery from hardware failures, accidental deletion, ransomware, or other catastrophic events.

---

## Responsible Disclosure

Please do not publicly disclose security vulnerabilities until a fix has been released or a coordinated disclosure has been agreed upon.

Responsible disclosure helps protect all users of the project.
