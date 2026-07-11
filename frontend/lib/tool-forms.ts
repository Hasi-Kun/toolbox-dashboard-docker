export type FieldType = "text" | "password" | "number" | "checkbox" | "select" | "int-list" | "string-list" | "textarea" | "checkbox-group" | "header-list";

export interface FieldOption {
  value: string;
  label: string;
}

export interface FieldSpec {
  name: string;
  label: string;
  type: FieldType;
  default?: string | number | boolean | string[];
  options?: FieldOption[];
  placeholder?: string;
  helpText?: string;
}

const RECORD_TYPE_OPTIONS: FieldOption[] = [
  "A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME", "SRV", "CAA",
].map((v) => ({ value: v, label: v }));

const ALL_DNS_RECORD_TYPE_OPTIONS: FieldOption[] = [
  "A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME", "SRV", "CAA",
  "PTR", "DNSKEY", "DS", "NAPTR", "TLSA", "HINFO", "RP", "LOC", "SSHFP", "NSEC",
].map((v) => ({ value: v, label: v }));

/**
 * Deklarative Formular-Beschreibung pro Tool-Slug. Bewusst hier zentral
 * gepflegt statt Backend-Schema-Introspection -- fuer 27 Tools mit
 * ueberschaubaren Eingaben ist das einfacher zu warten als ein generischer
 * JSON-Schema-Renderer, und neue Tools kommen selten genug hinzu, dass ein
 * paar Zeilen hier kein Problem sind.
 */
export const TOOL_FORMS: Record<string, FieldSpec[]> = {
  // --- DNS ---
  "dns-lookup": [
    { name: "domain", label: "Domain", type: "text", placeholder: "example.com" },
    { name: "record_types", label: "Record-Typen (Mehrfachauswahl)", type: "checkbox-group", options: ALL_DNS_RECORD_TYPE_OPTIONS, default: ["A", "AAAA", "MX", "TXT", "NS"] },
    { name: "custom_nameserver", label: "Custom-Nameserver (optional, z.B. 1.1.1.1)", type: "text", placeholder: "leer = System-Resolver" },
  ],
  "dns-reverse-lookup": [
    { name: "ip", label: "IP-Adresse", type: "text", placeholder: "8.8.8.8" },
  ],
  "dns-propagation": [
    { name: "domain", label: "Domain", type: "text", placeholder: "example.com" },
    { name: "record_type", label: "Record-Typ", type: "select", options: RECORD_TYPE_OPTIONS, default: "A" },
  ],
  "zone-transfer-check": [{ name: "domain", label: "Domain", type: "text", placeholder: "example.com" }],

  // --- Mail ---
  "spf-check": [{ name: "domain", label: "Domain", type: "text", placeholder: "example.com" }],
  "spf-ip-validator": [
    { name: "domain_or_email", label: "Domain oder E-Mail-Adresse", type: "text", placeholder: "example.com oder user@example.com" },
    { name: "ip", label: "Zu pruefende IP-Adresse", type: "text", placeholder: "203.0.113.55" },
  ],
  "dkim-check": [
    { name: "domain", label: "Domain", type: "text", placeholder: "example.com" },
    { name: "selector", label: "Selector (optional, sonst Fallback-Liste)", type: "text", placeholder: "z.B. google, default" },
  ],
  "dmarc-check": [{ name: "domain", label: "Domain", type: "text", placeholder: "example.com" }],

  // --- Network ---
  ping: [
    { name: "host", label: "Host", type: "text", placeholder: "1.1.1.1" },
    { name: "count", label: "Anzahl Pakete", type: "number", default: 4 },
  ],
  traceroute: [
    { name: "host", label: "Host", type: "text", placeholder: "1.1.1.1" },
    { name: "max_hops", label: "Max. Hops", type: "number", default: 20 },
  ],
  whois: [{ name: "target", label: "Domain oder IP", type: "text", placeholder: "example.com" }],
  "port-check": [
    { name: "host", label: "Host", type: "text", placeholder: "example.com" },
    { name: "ports", label: "Ports (max. 10, kommagetrennt)", type: "int-list", placeholder: "22, 80, 443" },
  ],

  // --- Security ---
  "ssl-checker": [
    { name: "host", label: "Host", type: "text", placeholder: "example.com" },
    { name: "port", label: "Port", type: "number", default: 443 },
  ],
  "security-headers": [{ name: "domain", label: "Domain", type: "text", placeholder: "example.com" }],
  "robots-txt": [{ name: "domain", label: "Domain", type: "text", placeholder: "example.com" }],
  "security-txt": [{ name: "domain", label: "Domain", type: "text", placeholder: "example.com" }],
  "tls-cipher-audit": [
    { name: "host", label: "Host", type: "text", placeholder: "example.com" },
    { name: "port", label: "Port", type: "number", default: 443 },
  ],
  "cors-checker": [{ name: "url", label: "URL", type: "text", placeholder: "https://api.example.com" }],
  "waf-detector": [{ name: "domain", label: "Domain", type: "text", placeholder: "example.com" }],
  "reflected-input-checker": [{ name: "url", label: "URL", type: "text", placeholder: "https://example.com/search" }],
  "open-redirect-checker": [{ name: "url", label: "URL", type: "text", placeholder: "https://example.com/login" }],
  "cookie-security-analyzer": [{ name: "domain", label: "Domain", type: "text", placeholder: "example.com" }],
  "http-methods-checker": [{ name: "url", label: "URL", type: "text", placeholder: "https://example.com" }],
  "password-breach-check": [{ name: "password", label: "Passwort (wird nie gespeichert)", type: "password", placeholder: "zu pruefendes Passwort" }],
  "jwt-security-analyzer": [{ name: "token", label: "JWT", type: "textarea", placeholder: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." }],

  // --- Nmap ---
  "nmap-quick": [{ name: "target", label: "Ziel", type: "text", placeholder: "example.com" }],
  "nmap-top-ports": [
    { name: "target", label: "Ziel", type: "text", placeholder: "example.com" },
    { name: "count", label: "Anzahl Ports (max. 1000)", type: "number", default: 100 },
  ],
  "nmap-service-detection": [
    { name: "target", label: "Ziel", type: "text", placeholder: "example.com" },
    { name: "ports", label: "Ports (max. 20, kommagetrennt)", type: "int-list", placeholder: "22, 80, 443" },
  ],
  "nmap-os-detection": [{ name: "target", label: "Ziel", type: "text", placeholder: "example.com" }],
  "nmap-aggressive": [{ name: "target", label: "Ziel", type: "text", placeholder: "example.com", helpText: "Langsamster Scan-Typ -- kann bis zu 2 Minuten dauern." }],
  "nmap-udp": [
    { name: "target", label: "Ziel", type: "text", placeholder: "example.com" },
    { name: "count", label: "Anzahl Ports (max. 50)", type: "number", default: 20 },
  ],
  "nikto-scan": [
    { name: "target", label: "Ziel (nur Systeme, fuer die du eine Erlaubnis hast)", type: "text", placeholder: "example.com", helpText: "Aktiver Scan mit tausenden Anfragen -- kann bis zu 3 Minuten dauern. Nur fuer Administratoren." },
  ],
  "nmap-host-discovery": [
    { name: "target", label: "Ziel", type: "text", placeholder: "example.com", helpText: "Reiner Ping-Scan -- prueft nur Erreichbarkeit, keine Ports." },
  ],
  "nmap-full-port-scan": [
    { name: "target", label: "Ziel", type: "text", placeholder: "example.com", helpText: "Scannt ALLE 65535 Ports -- kann mehrere Minuten dauern." },
  ],
  "nmap-vuln-scan": [
    { name: "target", label: "Ziel (nur Systeme, fuer die du eine Erlaubnis hast)", type: "text", placeholder: "example.com", helpText: "Nutzt nmaps 'vuln'-Script-Kategorie. Nur fuer Administratoren." },
  ],

  // --- testssl.sh ---
  "testssl-deep-scan": [
    { name: "target", label: "Ziel (nur Systeme, fuer die du eine Erlaubnis hast)", type: "text", placeholder: "example.com", helpText: "Gruendlicher TLS/SSL-Schwachstellen-Scan -- kann mehrere Minuten dauern. Nur fuer Administratoren." },
    { name: "port", label: "Port", type: "number", default: 443 },
  ],

  // --- Utilities ---
  "hash-generator": [
    { name: "text", label: "Text", type: "textarea" },
    {
      name: "algorithms",
      label: "Algorithmen",
      type: "checkbox-group",
      options: [
        { value: "md5", label: "MD5" },
        { value: "sha1", label: "SHA1" },
        { value: "sha256", label: "SHA256" },
        { value: "sha512", label: "SHA512" },
      ],
      default: ["md5", "sha1", "sha256", "sha512"],
    },
  ],
  "ntlm-hash-generator": [{ name: "password", label: "Passwort (wird nie gespeichert)", type: "password", placeholder: "zu hashendes Passwort" }],
  "base64-tool": [
    { name: "text", label: "Text", type: "textarea" },
    { name: "operation", label: "Operation", type: "select", options: [{ value: "encode", label: "Encode" }, { value: "decode", label: "Decode" }], default: "encode" },
  ],
  "jwt-decoder": [
    { name: "token", label: "JWT", type: "textarea", placeholder: "eyJhbGciOi..." },
    { name: "secret", label: "Secret (optional, fuer HS256/384/512-Verifikation)", type: "text" },
  ],
  "uuid-generator": [
    { name: "version", label: "Version", type: "select", options: [{ value: "4", label: "v4 (zufaellig)" }, { value: "1", label: "v1 (zeitbasiert)" }], default: "4" },
    { name: "count", label: "Anzahl (max. 50)", type: "number", default: 1 },
  ],
  "password-generator": [
    { name: "length", label: "Laenge", type: "number", default: 16 },
    { name: "count", label: "Anzahl (max. 20)", type: "number", default: 1 },
    { name: "use_uppercase", label: "Grossbuchstaben", type: "checkbox", default: true },
    { name: "use_lowercase", label: "Kleinbuchstaben", type: "checkbox", default: true },
    { name: "use_digits", label: "Zahlen", type: "checkbox", default: true },
    { name: "use_symbols", label: "Sonderzeichen", type: "checkbox", default: true },
  ],
  "cidr-calculator": [{ name: "cidr", label: "CIDR", type: "text", placeholder: "192.168.1.0/24" }],
  "timestamp-converter": [{ name: "value", label: "Unix-Timestamp oder ISO-8601-Datum", type: "text", placeholder: "1700000000" }],

  // --- Certificates ---
  "certificate-chain": [
    { name: "host", label: "Host", type: "text", placeholder: "example.com" },
    { name: "port", label: "Port", type: "number", default: 443 },
  ],
  "certificate-transparency": [
    { name: "domain", label: "Domain", type: "text", placeholder: "example.com" },
  ],

  // --- Website-Analyse ---
  "redirect-chain": [{ name: "url", label: "URL", type: "text", placeholder: "http://example.com" }],
  "meta-tags": [{ name: "domain", label: "Domain", type: "text", placeholder: "example.com" }],
  "response-time": [{ name: "domain", label: "Domain", type: "text", placeholder: "example.com" }],

  // --- Security (Ergaenzung) ---
  "vulnerability-indicators": [{ name: "domain", label: "Domain", type: "text", placeholder: "example.com" }],
  // --- Mail (Ergaenzung) ---
  "dane-check": [
    { name: "domain", label: "Domain", type: "text", placeholder: "example.com" },
    { name: "port", label: "Port", type: "number", default: 25 },
  ],
  "smtp-tls-check": [
    { name: "host", label: "Mailserver-Host", type: "text", placeholder: "mail.example.com" },
    { name: "port", label: "Port", type: "select", options: [{ value: "25", label: "25 (SMTP)" }, { value: "587", label: "587 (Submission)" }, { value: "465", label: "465 (SMTPS)" }], default: "25" },
  ],
  "blacklist-check": [{ name: "target", label: "Domain oder IP", type: "text", placeholder: "example.com" }],
  "ghost-sender-check": [{ name: "domain", label: "Domain", type: "text", placeholder: "example.com" }],
  "dkim-signature-inspector": [
    {
      name: "dkim_signature_header",
      label: "DKIM-Signature Kopfzeile (aus dem E-Mail-Header kopiert)",
      type: "textarea",
      placeholder: "v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector1; h=from:to:subject; bh=...; b=...",
    },
  ],
  "smtp-debug": [
    { name: "host", label: "Mailserver-Host", type: "text", placeholder: "mail.example.com" },
    { name: "port", label: "Port", type: "select", options: [{ value: "25", label: "25 (SMTP)" }, { value: "587", label: "587 (Submission)" }, { value: "465", label: "465 (SMTPS)" }], default: "25" },
    { name: "use_starttls", label: "STARTTLS versuchen", type: "checkbox", default: true },
    { name: "mail_from", label: "Absender (MAIL FROM)", type: "text", placeholder: "test@example.com" },
    { name: "rcpt_to", label: "Empfaenger (RCPT TO, kommagetrennt, max. 5)", type: "string-list", placeholder: "ziel@example.com" },
    { name: "subject", label: "Betreff", type: "text", default: "Toolbox SMTP Debug Test" },
    { name: "custom_headers", label: "Zusaetzliche Header (eine 'Name: Wert'-Zeile pro Header)", type: "header-list", placeholder: "Reply-To: antwort@example.com\nX-Priority: 1" },
    { name: "body", label: "Nachrichtentext", type: "textarea" },
    { name: "send_data", label: "Nachricht wirklich senden (sonst nur Verbindungs-/Relay-Test)", type: "checkbox", default: false },
  ],

  // --- Certificates (Ergaenzung) ---
  "ocsp-check": [
    { name: "host", label: "Host", type: "text", placeholder: "example.com" },
    { name: "port", label: "Port", type: "number", default: 443 },
  ],

  // --- Website-Analyse (Ergaenzung) ---
  "broken-links-checker": [{ name: "domain", label: "Domain", type: "text", placeholder: "example.com" }],
  "sitemap-check": [{ name: "domain", label: "Domain", type: "text", placeholder: "example.com" }],

  // --- Utilities (Ergaenzung) ---
  "ip-geolocation": [{ name: "target", label: "IP oder Domain", type: "text", placeholder: "8.8.8.8" }],
  "hash-identifier": [{ name: "hash_value", label: "Hash", type: "text", placeholder: "5d41402abc4b2a76b9719d911017c592" }],
  // --- Utilities (Ergaenzung) ---
  "fastviewer-status": [],

  // --- OSINT ---
  "subdomain-bruteforce": [{ name: "domain", label: "Domain", type: "text", placeholder: "example.com" }],
  "asn-lookup": [{ name: "target", label: "IP oder Domain", type: "text", placeholder: "8.8.8.8" }],
  "wayback-history": [{ name: "domain", label: "Domain", type: "text", placeholder: "example.com" }],
  "shodan-internetdb": [{ name: "ip", label: "IP-Adresse", type: "text", placeholder: "8.8.8.8" }],
  "sri-checker": [{ name: "url", label: "URL", type: "text", placeholder: "https://example.com" }],
  "domain-security-check": [{ name: "domain", label: "Domain", type: "text", placeholder: "example.com" }],
  "typosquat-checker": [{ name: "domain", label: "Domain", type: "text", placeholder: "example.com" }],
  "subdomain-takeover-checker": [{ name: "subdomain", label: "Subdomain", type: "text", placeholder: "forgotten.example.com" }],
  "cloud-bucket-finder": [{ name: "name", label: "Firmen-/Projektname", type: "text", placeholder: "meinefirma" }],
  "git-secrets-scanner": [
    { name: "query", label: "Suchbegriff (Domain/Firmenname)", type: "text", placeholder: "meinefirma.de" },
    { name: "github_token", label: "GitHub-Token (eigener, wird nie gespeichert)", type: "password", placeholder: "ghp_..." },
  ],
  "google-dork-generator": [{ name: "domain", label: "Domain", type: "text", placeholder: "example.com" }],
  "tech-fingerprint": [{ name: "domain", label: "Domain", type: "text", placeholder: "example.com" }],
};
