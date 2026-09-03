/**
 * Ordnet Toolbox-Tool-Slugs den passenden Cheatsheet-Eintraegen zu
 * (siehe lib/cheatsheets.ts) -- fuer das einklappbare Cheatsheet-Panel
 * direkt auf der jeweiligen Tool-Seite. Nicht jedes Tool hat eine
 * sinnvolle Entsprechung; nur eintragen, wo es wirklich passt.
 *
 * Format: Tool-Slug -> Liste von [Kategorie-Slug, Tool-Slug]-Paaren aus
 * cheatsheets.ts (meist genau einer, manchmal mehrere -- z.B. DNS-Tools
 * profitieren sowohl von "dig" als auch "host").
 */
export const TOOL_CHEATSHEET_MAP: Record<string, Array<[string, string]>> = {
  // DNS
  "dns-lookup": [["dns-network", "dig"], ["dns-network", "host"]],
  "dns-reverse-lookup": [["dns-network", "dig"], ["dns-network", "host"]],
  "dns-propagation": [["dns-network", "dig"]],
  "zone-transfer-check": [["dns-network", "dig"]],

  // Netzwerk
  whois: [["dns-network", "whois"]],
  traceroute: [["dns-network", "traceroute-mtr"]],
  ping: [["dns-network", "ping-fping"]],
  "port-check": [["port-scanning", "netcat"]],
  "ip-geolocation": [["dns-network", "whois"]],

  // Scanner
  "nmap-quick": [["port-scanning", "nmap"]],
  "nmap-top-ports": [["port-scanning", "nmap"]],
  "nmap-service-detection": [["port-scanning", "nmap"]],
  "nmap-os-detection": [["port-scanning", "nmap"]],
  "nmap-aggressive": [["port-scanning", "nmap"]],
  "nmap-udp": [["port-scanning", "nmap"]],
  "nmap-host-discovery": [["port-scanning", "nmap"]],
  "nmap-full-port-scan": [["port-scanning", "nmap"]],
  "nmap-vuln-scan": [["port-scanning", "nmap"]],
  "nikto-scan": [["http-web", "nikto"]],
  "testssl-deep-scan": [["tls-crypto", "sslscan-testssl"]],

  // Security / TLS
  "ssl-checker": [["tls-crypto", "openssl"]],
  "tls-cipher-audit": [["tls-crypto", "openssl"], ["tls-crypto", "sslscan-testssl"]],
  "certificate-chain": [["tls-crypto", "openssl"]],
  "certificate-transparency": [["tls-crypto", "openssl"]],
  "ocsp-check": [["tls-crypto", "openssl"]],
  "security-headers": [["http-web", "curl"]],
  "http-methods-checker": [["http-web", "curl"]],
  "cors-checker": [["http-web", "curl"]],
  "open-redirect-checker": [["http-web", "curl"]],
  "reflected-input-checker": [["http-web", "curl"]],
  "waf-detector": [["http-web", "curl"]],
  "exposed-files-checker": [["port-scanning", "netcat"], ["http-web", "content-discovery"]],
  "password-breach-check": [["hashing-forensics", "hashcat-john"]],
  "subdomain-bruteforce": [["http-web", "content-discovery"]],

  // Website
  "redirect-chain": [["http-web", "curl"]],
  "response-time": [["http-web", "curl"]],
  "broken-links-checker": [["http-web", "curl"]],
  "curl-browser": [["http-web", "curl"], ["http-web", "httpie"]],

  // Converter
  "hash-generator": [["hashing-forensics", "checksums"]],
  "hash-identifier": [["hashing-forensics", "hashcat-john"]],
  "ntlm-hash-generator": [["hashing-forensics", "hashcat-john"]],

  // Zertifikate (Sonderseite)
  "openssl-file-inspector": [["tls-crypto", "openssl"]],

  // OSINT
  "shodan-internetdb": [["port-scanning", "nmap"]],
  "ip-threat-intel": [["dns-network", "whois"]],
};
