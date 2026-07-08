"""Web-Technologie-Fingerprinting (in der Art von WhatWeb/Wappalyzer),
aber als reine Python/HTTP-Signaturpruefung ohne externe Laufzeitumgebung
oder Fremd-Binary. Bewusst so gebaut statt eine echte WhatWeb- (Ruby-)
oder Wappalyzer-Integration einzubinden: nach der muehsamen Mehrfach-
Fehlersuche bei der Nikto-Integration (Perl-Abhaengigkeiten) sollte hier
keine dritte Laufzeitumgebung (Ruby) mit eigenen, in dieser Umgebung
nicht live testbaren Abhaengigkeiten dazukommen. Wappalyzers eigentliche
Fingerprint-Datenbank ist ausserdem mittlerweile kommerziell/proprietaer
(nach der Kommerzialisierung des Projekts) -- Community-Forks nutzen
einen veralteten Datenstand.
"""

import re

import httpx
from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname

# (Header-Name, Teilstring-Muster ("" = Header muss nur existieren), Technologie, Kategorie)
_HEADER_SIGNATURES: list[tuple[str, str, str, str]] = [
    ("server", "cloudflare", "Cloudflare", "CDN/Security"),
    ("server", "nginx", "nginx", "Webserver"),
    ("server", "apache", "Apache", "Webserver"),
    ("server", "microsoft-iis", "Microsoft IIS", "Webserver"),
    ("server", "litespeed", "LiteSpeed", "Webserver"),
    ("server", "caddy", "Caddy", "Webserver"),
    ("server", "kestrel", "Kestrel (ASP.NET Core)", "Webserver"),
    ("server", "openresty", "OpenResty", "Webserver"),
    ("x-powered-by", "php", "PHP", "Sprache/Framework"),
    ("x-powered-by", "asp.net", "ASP.NET", "Sprache/Framework"),
    ("x-powered-by", "express", "Express (Node.js)", "Sprache/Framework"),
    ("x-powered-by", "next.js", "Next.js", "JS-Framework"),
    ("x-generator", "wordpress", "WordPress", "CMS"),
    ("x-generator", "drupal", "Drupal", "CMS"),
    ("x-drupal-cache", "", "Drupal", "CMS"),
    ("x-varnish", "", "Varnish Cache", "CDN/Security"),
    ("cf-ray", "", "Cloudflare", "CDN/Security"),
    ("x-sucuri-id", "", "Sucuri", "CDN/Security"),
    ("x-akamai-transformed", "", "Akamai", "CDN/Security"),
    ("fly-request-id", "", "Fly.io", "Hosting"),
    ("x-vercel-id", "", "Vercel", "Hosting"),
    ("x-nf-request-id", "", "Netlify", "Hosting"),
    ("x-github-request-id", "", "GitHub Pages", "Hosting"),
    ("x-shopify-stage", "", "Shopify", "E-Commerce"),
    ("x-magento-cache-debug", "", "Magento", "E-Commerce"),
    ("x-turbo-charged-by", "litespeed", "LiteSpeed Cache", "Webserver"),
]

_BODY_SIGNATURES: list[tuple[str, str, str]] = [
    # CMS
    (r"wp-content|wp-includes", "WordPress", "CMS"),
    (r"/sites/default/files|Drupal\.settings", "Drupal", "CMS"),
    (r"Joomla!", "Joomla", "CMS"),
    (r"typo3(?:temp|conf)", "TYPO3", "CMS"),
    (r"content=\"Ghost", "Ghost", "CMS"),
    (r"static\.wixstatic\.com|wix\.com", "Wix", "CMS"),
    (r"squarespace\.com|static1\.squarespace", "Squarespace", "CMS"),
    (r"webflow\.com|\.webflow\.io", "Webflow", "CMS"),
    (r"craftcms|craft-cms", "Craft CMS", "CMS"),
    (r"contao", "Contao", "CMS"),
    # E-Commerce
    (r"cdn\.shopify\.com|shopify\.com", "Shopify", "E-Commerce"),
    (r"woocommerce", "WooCommerce", "E-Commerce"),
    (r"Mage\.Cookies|/skin/frontend/", "Magento", "E-Commerce"),
    (r"prestashop", "PrestaShop", "E-Commerce"),
    (r"bigcommerce", "BigCommerce", "E-Commerce"),
    # JS-Frameworks
    (r"react-dom|__NEXT_DATA__|_next/static", "React / Next.js", "JS-Framework"),
    (r"ng-version=|angular\.io", "Angular", "JS-Framework"),
    (r"vue\.js|__VUE__|__NUXT__", "Vue.js / Nuxt", "JS-Framework"),
    (r"svelte-", "Svelte", "JS-Framework"),
    (r"jquery(?:\.min)?\.js", "jQuery", "JS-Framework"),
    (r"ember\.js|data-ember-", "Ember.js", "JS-Framework"),
    (r"alpinejs|x-data=", "Alpine.js", "JS-Framework"),
    (r"htmx\.org|hx-get=|hx-post=", "htmx", "JS-Framework"),
    # CSS-Frameworks
    (r"bootstrap(?:\.min)?\.css", "Bootstrap", "CSS-Framework"),
    (r"tailwindcss|tailwind\.css", "Tailwind CSS", "CSS-Framework"),
    (r"bulma(?:\.min)?\.css", "Bulma", "CSS-Framework"),
    (r"foundation(?:\.min)?\.css", "Foundation", "CSS-Framework"),
    # Analytics/Tracking
    (r"google-site-verification", "Google Search Console", "Analytics"),
    (r"gtag\(|google-analytics\.com|googletagmanager\.com", "Google Analytics/Tag Manager", "Analytics"),
    (r"hs-scripts\.com|hubspot", "HubSpot", "Marketing"),
    (r"matomo\.js|piwik\.js", "Matomo/Piwik", "Analytics"),
    (r"hotjar\.com|hjid", "Hotjar", "Analytics"),
    (r"mixpanel\.com", "Mixpanel", "Analytics"),
    (r"cdn\.segment\.com|analytics\.js", "Segment", "Analytics"),
    (r"connect\.facebook\.net|fbq\(", "Facebook Pixel", "Analytics"),
    (r"clarity\.ms", "Microsoft Clarity", "Analytics"),
    # Chat/Support-Widgets
    (r"widget\.intercom\.io", "Intercom", "Chat/Support"),
    (r"static\.zdassets\.com|zendesk", "Zendesk", "Chat/Support"),
    (r"js\.driftt\.com|drift\.com", "Drift", "Chat/Support"),
    (r"tawk\.to", "Tawk.to", "Chat/Support"),
    (r"crisp\.chat", "Crisp", "Chat/Support"),
    (r"embed\.typeform\.com", "Typeform", "Formulare"),
    # Payment
    (r"js\.stripe\.com", "Stripe", "Zahlungsanbieter"),
    (r"paypal\.com/sdk", "PayPal", "Zahlungsanbieter"),
    (r"braintreegateway\.com", "Braintree", "Zahlungsanbieter"),
    # Fonts/CDN-Assets
    (r"fonts\.googleapis\.com", "Google Fonts", "Fonts"),
    (r"use\.typekit\.net", "Adobe Fonts", "Fonts"),
    (r"cdnjs\.cloudflare\.com", "cdnjs", "CDN/Security"),
    (r"unpkg\.com", "unpkg CDN", "CDN/Security"),
    # Security/CAPTCHA
    (r"recaptcha|google\.com/recaptcha", "Google reCAPTCHA", "Security"),
    (r"hcaptcha\.com", "hCaptcha", "Security"),
    (r"cloudflare\.com/turnstile", "Cloudflare Turnstile", "Security"),
]


@register_module
class TechFingerprintModule(ToolModule):
    slug = "tech-fingerprint"
    category = "osint"
    name = "Web Technology Fingerprint"
    description = (
        "Erkennt CMS/Framework/Analytics/E-Commerce/Hosting-Hinweise einer Website anhand von "
        "HTTP-Headern und Seiteninhalt (aehnlich WhatWeb/Wappalyzer, aber als reine "
        "Python/HTTP-Signaturpruefung ohne Fremd-Laufzeitumgebung -- ueber 60 Signaturen in "
        "9 Kategorien)."
    )
    is_active_scan = False
    timeout_seconds = 12

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
            if not is_valid_hostname(v):
                raise ValueError("Ungueltige Domain")
            return v

    class Output(BaseModel):
        domain: str
        success: bool
        final_url: str | None = None
        server_header: str | None = None
        detected_by_category: dict[str, list[str]] = {}
        detected_technologies: list[str] = []
        response_headers: dict[str, str] = {}
        error: str | None = None

    async def run(self, data: Input) -> Output:
        detected: dict[str, set[str]] = {}

        def add(tech: str, cat: str) -> None:
            detected.setdefault(cat, set()).add(tech)

        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds, follow_redirects=True) as client:
                response = await client.get(
                    f"https://{data.domain}", headers={"User-Agent": "Mozilla/5.0 (compatible; Toolbox-Fingerprint/1.0)"}
                )
        except httpx.HTTPError as exc:
            return self.Output(domain=data.domain, success=False, error=str(exc))

        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        for header_name, pattern, tech, cat in _HEADER_SIGNATURES:
            value = headers_lower.get(header_name, "")
            if pattern == "" and header_name in headers_lower:
                add(tech, cat)
            elif pattern and pattern.lower() in value.lower():
                add(tech, cat)

        body_sample = response.text[:300_000]
        for pattern, tech, cat in _BODY_SIGNATURES:
            if re.search(pattern, body_sample, re.IGNORECASE):
                add(tech, cat)

        detected_by_category = {cat: sorted(techs) for cat, techs in sorted(detected.items())}
        flat = sorted({tech for techs in detected.values() for tech in techs})

        return self.Output(
            domain=data.domain, success=True, final_url=str(response.url),
            server_header=headers_lower.get("server"),
            detected_by_category=detected_by_category,
            detected_technologies=flat,
            response_headers=dict(response.headers),
            error=None,
        )
