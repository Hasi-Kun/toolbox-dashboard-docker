import asyncio
import smtplib

from pydantic import BaseModel, EmailStr, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname


def _decode(msg: bytes | str) -> str:
    return msg.decode("utf-8", errors="replace") if isinstance(msg, bytes) else str(msg)


def _run_smtp_debug_sync(
    host: str, port: int, use_starttls: bool, mail_from: str, rcpt_to: list[str],
    headers: dict[str, str], subject: str, body: str, send_data: bool, timeout: float,
) -> tuple[list[str], bool]:
    transcript: list[str] = []
    delivered = False

    smtp = smtplib.SMTP(timeout=timeout)
    try:
        code, msg = smtp.connect(host, port)
        transcript.append(f"< {code} {_decode(msg)}")

        code, msg = smtp.ehlo("toolbox-smtp-debug")
        transcript.append("> EHLO toolbox-smtp-debug")
        transcript.append(f"< {code} {_decode(msg)}")

        if use_starttls:
            if smtp.has_extn("starttls"):
                transcript.append("> STARTTLS")
                code, msg = smtp.docmd("STARTTLS")
                transcript.append(f"< {code} {_decode(msg)}")
                if code == 220:
                    smtp.starttls()
                    transcript.append("[TLS-Handshake erfolgreich]")
                    code, msg = smtp.ehlo("toolbox-smtp-debug")
                    transcript.append("> EHLO toolbox-smtp-debug (nach STARTTLS)")
                    transcript.append(f"< {code} {_decode(msg)}")
            else:
                transcript.append("[STARTTLS angefordert, aber vom Server nicht beworben -- uebersprungen]")

        transcript.append(f"> MAIL FROM:<{mail_from}>")
        code, msg = smtp.mail(mail_from)
        transcript.append(f"< {code} {_decode(msg)}")
        if code >= 400:
            transcript.append("[MAIL FROM abgelehnt -- Abbruch]")
            smtp.quit()
            return transcript, delivered

        accepted: list[str] = []
        for rcpt in rcpt_to:
            transcript.append(f"> RCPT TO:<{rcpt}>")
            code, msg = smtp.rcpt(rcpt)
            transcript.append(f"< {code} {_decode(msg)}")
            if code in (250, 251):
                accepted.append(rcpt)

        if not send_data:
            transcript.append(
                "> QUIT  (DATA bewusst nicht gesendet -- reiner Verbindungs-/Relay-Test, "
                "keine Nachricht wurde uebermittelt)"
            )
            smtp.quit()
            return transcript, delivered

        if not accepted:
            transcript.append("[Kein Empfaenger akzeptiert -- DATA wird nicht gesendet]")
            smtp.quit()
            return transcript, delivered

        message_lines = [f"{k}: {v}" for k, v in headers.items()]
        message_lines.append(f"From: {mail_from}")
        message_lines.append(f"To: {', '.join(accepted)}")
        message_lines.append(f"Subject: {subject}")
        message_lines.append("")
        message_lines.append(body or "(Testnachricht ohne Textinhalt)")
        full_message = "\r\n".join(message_lines)

        transcript.append(f"> DATA ... ({len(full_message)} Zeichen Nachrichteninhalt) ...")
        code, msg = smtp.data(full_message)
        transcript.append(f"< {code} {_decode(msg)}")
        delivered = code == 250

        transcript.append("> QUIT")
        smtp.quit()
    except (smtplib.SMTPException, OSError) as exc:
        transcript.append(f"[FEHLER: {exc}]")
    finally:
        try:
            smtp.close()
        except Exception:  # noqa: BLE001
            pass

    return transcript, delivered


@register_module
class SmtpDebugModule(ToolModule):
    slug = "smtp-debug"
    category = "mail"
    name = "SMTP Debug"
    description = (
        "Fuehrt eine vollstaendige, geskriptete SMTP-Sitzung gegen einen Mailserver aus und zeigt "
        "den kompletten Protokoll-Verlauf. Ohne 'Nachricht wirklich senden' stoppt der Test nach "
        "RCPT TO (reiner Verbindungs-/Relay-Test). Nur fuer Administratoren."
    )
    is_active_scan = False
    requires_admin = True
    timeout_seconds = 25

    class Input(BaseModel):
        host: str
        port: int = 25
        use_starttls: bool = True
        mail_from: EmailStr
        rcpt_to: list[EmailStr]
        subject: str = "Toolbox SMTP Debug Test"
        body: str = ""
        custom_headers: dict[str, str] = {}
        send_data: bool = False

        @field_validator("host")
        @classmethod
        def validate_host(cls, v: str) -> str:
            v = v.strip().rstrip(".")
            if not is_valid_hostname(v):
                raise ValueError("Ungueltiger Host")
            return v

        @field_validator("port")
        @classmethod
        def validate_port(cls, v: int) -> int:
            if v not in (25, 587, 465):
                raise ValueError("Port muss 25, 587 oder 465 sein")
            return v

        @field_validator("rcpt_to")
        @classmethod
        def validate_rcpt_count(cls, v: list[str]) -> list[str]:
            if not v:
                raise ValueError("Mindestens ein Empfaenger noetig")
            if len(v) > 5:
                raise ValueError("Maximal 5 Empfaenger pro Test")
            return v

        @field_validator("custom_headers")
        @classmethod
        def validate_headers(cls, v: dict[str, str]) -> dict[str, str]:
            if len(v) > 15:
                raise ValueError("Maximal 15 zusaetzliche Header")
            return v

        @field_validator("body")
        @classmethod
        def validate_body(cls, v: str) -> str:
            if len(v) > 5000:
                raise ValueError("Body darf maximal 5000 Zeichen haben")
            return v

    class Output(BaseModel):
        host: str
        port: int
        transcript: list[str]
        message_delivered: bool
        warning: str

    async def run(self, data: Input) -> Output:
        transcript, delivered = await asyncio.wait_for(
            asyncio.to_thread(
                _run_smtp_debug_sync, data.host, data.port, data.use_starttls, data.mail_from,
                list(data.rcpt_to), data.custom_headers, data.subject, data.body, data.send_data,
                float(self.timeout_seconds - 3),
            ),
            timeout=self.timeout_seconds - 1,
        )

        warning = (
            "Es wurde eine ECHTE Testnachricht zugestellt." if delivered
            else "Es wurde keine Nachricht zugestellt (reiner Verbindungstest oder abgelehnt)."
        )

        return self.Output(
            host=data.host, port=data.port, transcript=transcript,
            message_delivered=delivered, warning=warning,
        )
