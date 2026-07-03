export type FieldType = "text" | "number" | "checkbox" | "select" | "int-list" | "textarea" | "checkbox-group";

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
    { name: "record_type", label: "Record-Typ", type: "select", options: RECORD_TYPE_OPTIONS, default: "A" },
  ],
  "dns-reverse-lookup": [
    { name: "ip", label: "IP-Adresse", type: "text", placeholder: "8.8.8.8" },
  ],
  "dns-propagation": [
    { name: "domain", label: "Domain", type: "text", placeholder: "example.com" },
    { name: "record_type", label: "Record-Typ", type: "select", options: RECORD_TYPE_OPTIONS, default: "A" },
  ],

  // --- Mail ---
  "spf-check": [{ name: "domain", label: "Domain", type: "text", placeholder: "example.com" }],
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
};
