/**
 * Unterkategorien innerhalb jeder Hauptkategorie -- rein visuelle
 * Gruppierung auf der Kategorie-Seite (Tools bleiben in ihrer
 * bestehenden Hauptkategorie, keine Backend-Aenderung noetig, kein
 * Risiko fuer stale category-Referenzen wie bei der letzten
 * Reorganisation). Tools ohne Eintrag hier landen automatisch in einer
 * "Weitere"-Gruppe am Ende, statt zu verschwinden.
 *
 * Format: Kategorie-Slug -> Liste von Gruppen (Name + Tool-Slugs in
 * gewuenschter Reihenfolge).
 */
export const SUBCATEGORIES: Record<string, Array<{ name: string; tools: string[] }>> = {
  security: [
    { name: "TLS & Verschluesselung", tools: ["ssl-checker", "tls-cipher-audit"] },
    {
      name: "HTTP-Header & Konfiguration",
      tools: ["security-headers", "cors-checker", "http-methods-checker", "cookie-security-analyzer", "sri-checker", "waf-detector", "open-redirect-checker", "reflected-input-checker"],
    },
    { name: "Schwachstellen & Exposition", tools: ["vulnerability-indicators", "exposed-files-checker", "log4j-vuln-tester", "ssh-security-check", "canary-token-scan"] },
    { name: "Auth & Tokens", tools: ["jwt-security-analyzer", "password-breach-check"] },
    { name: "Domain-Gesamtbewertung & Richtliniendateien", tools: ["domain-security-check", "robots-txt", "security-txt"] },
  ],
  osint: [
    {
      name: "Subdomains & Infrastruktur",
      tools: ["subdomain-bruteforce", "subdomain-takeover-checker", "subdomain-takeover-batch-checker", "asn-lookup", "shodan-internetdb", "ip-threat-intel", "cloud-bucket-finder", "typosquat-checker"],
    },
    { name: "Aufklaerung & Historie", tools: ["email-harvester", "email-domain-leak-finder", "google-dork-generator", "wayback-history", "git-secrets-scanner", "tech-fingerprint"] },
    { name: "Schwachstellen-Datenbank", tools: ["cve-lookup"] },
  ],
  mail: [
    { name: "SPF / DKIM / DMARC", tools: ["spf-check", "spf-ip-validator", "dkim-check", "dkim-signature-inspector", "dkim-validator", "dmarc-check"] },
    { name: "Server & Zustellung", tools: ["smtp-debug", "smtp-tls-check", "dane-check", "blacklist-check", "ghost-sender-check"] },
  ],
  scanner: [
    {
      name: "Nmap",
      tools: ["nmap-quick", "nmap-top-ports", "nmap-service-detection", "nmap-os-detection", "nmap-aggressive", "nmap-udp", "nmap-host-discovery", "nmap-full-port-scan", "nmap-vuln-scan"],
    },
    { name: "Web- & TLS-Scanner", tools: ["nikto-scan", "testssl-deep-scan"] },
  ],
  converter: [
    { name: "Encoding & Format", tools: ["base64-tool", "json-formatter", "jwt-decoder", "timestamp-converter"] },
    { name: "Generatoren", tools: ["password-generator", "uuid-generator", "hash-generator", "ntlm-hash-generator"] },
    { name: "Identifikation & Berechnung", tools: ["hash-identifier", "cidr-calculator"] },
  ],
  network: [
    { name: "Erreichbarkeit", tools: ["ping", "traceroute", "port-check"] },
    { name: "Lookup", tools: ["whois", "ip-geolocation", "fastviewer-status"] },
  ],
  website: [
    { name: "Analyse", tools: ["meta-tags", "sitemap-check", "broken-links-checker", "response-time", "redirect-chain"] },
    { name: "Werkzeug", tools: ["curl-browser"] },
  ],
  dns: [
    { name: "Lookup", tools: ["dns-lookup", "dns-reverse-lookup"] },
    { name: "Diagnose", tools: ["dns-health-check", "dns-propagation", "zone-transfer-check"] },
  ],
  certificates: [
    { name: "Zertifikatspruefung", tools: ["certificate-chain", "certificate-transparency", "ocsp-check", "openssl-file-inspector"] },
  ],
};
