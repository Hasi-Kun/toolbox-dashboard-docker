import asyncio
import re

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import ocsp
from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname, is_valid_ip

_CERT_BLOCK_RE = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL)


def _fetch_chain_pems(host: str, port: int, timeout: float) -> list[str]:
    """Blockierender openssl-Aufruf -- ueber asyncio.to_thread aufgerufen.
    Gleicher Ansatz wie im certificate-chain-Modul."""
    import subprocess

    result = subprocess.run(
        ["openssl", "s_client", "-connect", f"{host}:{port}", "-showcerts"],
        input=b"", capture_output=True, timeout=timeout,
    )
    output = result.stdout.decode("utf-8", errors="replace")
    return _CERT_BLOCK_RE.findall(output)


@register_module
class OcspCheckModule(ToolModule):
    slug = "ocsp-check"
    category = "certificates"
    name = "OCSP Check"
    description = "Prueft den Widerrufsstatus eines Zertifikats live beim OCSP-Responder des Ausstellers."
    is_active_scan = False
    timeout_seconds = 15

    class Input(BaseModel):
        host: str
        port: int = 443

        @field_validator("host")
        @classmethod
        def validate_host(cls, v: str) -> str:
            v = v.strip().rstrip(".")
            if not (is_valid_hostname(v) or is_valid_ip(v)):
                raise ValueError("Ungueltiger Host")
            return v

        @field_validator("port")
        @classmethod
        def validate_port(cls, v: int) -> int:
            if not (1 <= v <= 65535):
                raise ValueError("Ungueltiger Port")
            return v

    class Output(BaseModel):
        host: str
        port: int
        success: bool
        ocsp_responder_url: str | None = None
        certificate_status: str | None = None
        revocation_time: str | None = None
        warnings: list[str] = []
        error: str | None = None

    async def run(self, data: Input) -> Output:
        try:
            pems = await asyncio.wait_for(
                asyncio.to_thread(_fetch_chain_pems, data.host, data.port, float(self.timeout_seconds - 8)),
                timeout=self.timeout_seconds - 5,
            )
        except asyncio.TimeoutError:
            return self.Output(host=data.host, port=data.port, success=False, error="Zeitueberschreitung beim Verbindungsaufbau")
        except Exception as exc:  # noqa: BLE001
            return self.Output(host=data.host, port=data.port, success=False, error=str(exc))

        if len(pems) < 2:
            return self.Output(
                host=data.host, port=data.port, success=False,
                error="Kein Zwischenzertifikat erhalten -- OCSP-Pruefung braucht Leaf + Issuer-Zertifikat.",
            )

        try:
            leaf_cert = x509.load_pem_x509_certificate(pems[0].encode())
            issuer_cert = x509.load_pem_x509_certificate(pems[1].encode())
        except Exception as exc:  # noqa: BLE001
            return self.Output(host=data.host, port=data.port, success=False, error=f"Zertifikat konnte nicht gelesen werden: {exc}")

        responder_url = self._get_ocsp_url(leaf_cert)
        if not responder_url:
            return self.Output(
                host=data.host, port=data.port, success=False,
                warnings=["Zertifikat enthaelt keine OCSP-Responder-URL (Authority Information Access fehlt)."],
                error=None,
            )

        try:
            builder = ocsp.OCSPRequestBuilder()
            builder = builder.add_cert(leaf_cert, issuer_cert, hashes.SHA1())
            ocsp_request = builder.build()
            request_der = ocsp_request.public_bytes(x509.Encoding.DER)

            async with httpx.AsyncClient(timeout=self.timeout_seconds - 10) as client:
                response = await client.post(
                    responder_url,
                    content=request_der,
                    headers={"Content-Type": "application/ocsp-request"},
                )
            ocsp_response = ocsp.load_der_ocsp_response(response.content)
        except Exception as exc:  # noqa: BLE001
            return self.Output(
                host=data.host, port=data.port, success=False, ocsp_responder_url=responder_url,
                error=f"OCSP-Anfrage fehlgeschlagen: {exc}",
            )

        if ocsp_response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
            return self.Output(
                host=data.host, port=data.port, success=False, ocsp_responder_url=responder_url,
                error=f"OCSP-Responder antwortete mit Status: {ocsp_response.response_status.name}",
            )

        status_map = {
            ocsp.OCSPCertStatus.GOOD: "good",
            ocsp.OCSPCertStatus.REVOKED: "revoked",
            ocsp.OCSPCertStatus.UNKNOWN: "unknown",
        }
        status = status_map.get(ocsp_response.certificate_status, "unknown")

        warnings: list[str] = []
        if status == "revoked":
            warnings.append("Zertifikat wurde WIDERRUFEN.")
        elif status == "unknown":
            warnings.append("OCSP-Responder kennt dieses Zertifikat nicht (evtl. falscher Responder oder sehr neues Zertifikat).")

        return self.Output(
            host=data.host, port=data.port, success=True, ocsp_responder_url=responder_url,
            certificate_status=status,
            revocation_time=ocsp_response.revocation_time.isoformat() if ocsp_response.revocation_time else None,
            warnings=warnings, error=None,
        )

    @staticmethod
    def _get_ocsp_url(cert: x509.Certificate) -> str | None:
        try:
            aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
        except x509.ExtensionNotFound:
            return None

        for access_description in aia.value:
            if access_description.access_method == x509.AuthorityInformationAccessOID.OCSP:
                return access_description.access_location.value
        return None
