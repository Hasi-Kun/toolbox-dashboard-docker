"""Erkennt gaengige Web Application Firewalls (WAF) und CDNs anhand von
HTTP-Response-Headern und Cookie-Namen -- rein passiv, ein einzelner
GET-Request, keine Angriffs-Payloads.
"""

import httpx
from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname, is_valid_ip

# (Header-Name, Teilstring-Muster, Anbieter) -- bewusst einfache,
# dokumentierte Signaturen statt eines grossen Fingerprint-Datensatzes.
_HEADER_SIGNATURES: list[tuple[str, str, str]] = [
    ("server", "cloudflare", "Cloudflare"),
    ("cf-ray", "", "Cloudflare"),
    ("x-sucuri-id", "", "Sucuri"),
    ("x-sucuri-cache", "", "Sucuri"),
    ("server", "airee", "Airee WAF"),
    ("x-akamai-transformed", "", "Akamai"),
    ("akamai-grn", "", "Akamai"),
    ("x-cdn", "imperva", "Imperva Incapsula"),
    ("x-iinfo", "", "Imperva Incapsula"),
    ("server", "cloudfront", "Amazon CloudFront"),
    ("x-amz-cf-id", "", "Amazon CloudFront"),
    ("server", "awselb", "AWS Elastic Load Balancer"),
    ("x-azure-ref", "", "Azure Front Door / WAF"),
    ("x-fd-int-roxy-purgeid", "", "Azure Front Door"),
    ("server", "cf-nginx", "Cloudflare"),
    ("x-cache", "cloudfront", "Amazon CloudFront"),
    ("x-datadome", "", "DataDome"),
    ("x-distil-cs", "", "Distil Networks / Imperva Bot Manager"),
    ("server", "ddos-guard", "DDoS-Guard"),
    ("x-vps-cache", "", "Varnish"),
]

_COOKIE_SIGNATURES: list[tuple[str, str]] = [
    ("incap_ses", "Imperva Incapsula"),
    ("visid_incap", "Imperva Incapsula"),
    ("__cfduid", "Cloudflare"),
    ("__cf_bm", "Cloudflare Bot Management"),
    ("citrix_ns_id", "Citrix ADC / NetScaler"),
    ("ak_bmsc", "Akamai Bot Manager"),
    ("bm_sz", "Akamai Bot Manager"),
    ("datadome", "DataDome"),
    ("_awssig", "AWS WAF"),
]


@register_module
class WafDetectorModule(ToolModule):
    slug = "waf-detector"
    category = "security"
    name = "WAF/CDN-Detector"
    description = (
        "Erkennt gaengige Web Application Firewalls und CDNs (Cloudflare, Akamai, Imperva, AWS WAF, "
        "Azure Front Door, DataDome u.a.) anhand von HTTP-Response-Headern und Cookie-Namen -- ein "
        "einzelner passiver GET-Request, keine Angriffs-Payloads."
    )
    is_active_scan = False
    timeout_seconds = 10

    class Input(BaseModel):
        domain: str

        @field_validator("domain")
        @classmethod
        def validate_domain(cls, v: str) -> str:
            v = v.strip().rstrip("/")
            for prefix in ("https://", "http://"):
                if v.startswith(prefix):
                    v = v[len(prefix):]
            v = v.split("/")[0]
            if not (is_valid_hostname(v) or is_valid_ip(v)):
                raise ValueError("Ungueltige Domain")
            return v

    class Output(BaseModel):
        domain: str
        success: bool
        detected: list[str] = []
        server_header: str | None = None
        error: str | None = None

    async def run(self, data: Input) -> Output:
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds, follow_redirects=True) as client:
                response = await client.get(
                    f"https://{data.domain}", headers={"User-Agent": "Mozilla/5.0 (compatible; Toolbox-WAF-Detector/1.0)"}
                )
        except httpx.HTTPError as exc:
            return self.Output(domain=data.domain, success=False, error=str(exc))

        detected: set[str] = set()
        headers_lower = {k.lower(): v for k, v in response.headers.items()}

        for header_name, pattern, vendor in _HEADER_SIGNATURES:
            value = headers_lower.get(header_name, "")
            if pattern == "" and header_name in headers_lower:
                detected.add(vendor)
            elif pattern and pattern.lower() in value.lower():
                detected.add(vendor)

        cookie_names = " ".join(response.cookies.keys()).lower()
        for cookie_name, vendor in _COOKIE_SIGNATURES:
            if cookie_name.lower() in cookie_names:
                detected.add(vendor)

        return self.Output(
            domain=data.domain, success=True, detected=sorted(detected),
            server_header=headers_lower.get("server"),
        )
