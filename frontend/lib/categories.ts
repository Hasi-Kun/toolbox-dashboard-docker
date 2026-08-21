export type Category = {
  slug: string;
  name: string;
  description: string;
  // Wird in Phase 2+ befuellt, sobald echte Module existieren.
  toolCount: number;
};

// Reihenfolge = Reihenfolge in der Sidebar.
//
// Kategorien-Reorganisation: "nmap" wurde zu "scanner" umbenannt und
// die frueher eigenstaendige "testssl"-Kategorie (nur 1 Tool) wurde
// dort mit hineingefuehrt -- alle aktiven Scan-Tools (Nmap, Nikto,
// testssl.sh) jetzt an einem Ort statt kuenstlich nach Werkzeugname
// getrennt. "utilities" wurde zu "converter" verschlankt (reine
// Format-Konvertierung/-Generierung); IP-Geolocation und der
// FastViewer-Statuscheck sind dafuer nach "network" gewandert, da sie
// inhaltlich Lookup-/Connectivity-Tools sind, keine Konverter.
export const categories: Category[] = [
  { slug: "dns", name: "DNS", description: "Lookup, Records, Propagation", toolCount: 4 },
  { slug: "mail", name: "Mail", description: "SMTP, SPF, DKIM, DMARC, DANE, Blacklist", toolCount: 10 },
  { slug: "network", name: "Netzwerk", description: "Ping, Traceroute, Whois, Geolocation", toolCount: 6 },
  { slug: "scanner", name: "Scanner", description: "Nmap, Nikto, testssl.sh -- aktive Scans", toolCount: 11 },
  { slug: "security", name: "Security", description: "SSL, Header, Score, CVE", toolCount: 18 },
  { slug: "website", name: "Website-Analyse", description: "Performance, SEO, Links", toolCount: 5 },
  { slug: "converter", name: "Converter", description: "Formatumwandlung, Hashes, Generatoren", toolCount: 10 },
  { slug: "certificates", name: "Zertifikate", description: "SSL-Ketten, Ablauf, OCSP", toolCount: 4 },
  { slug: "osint", name: "OSINT", description: "Subdomains, ASN, Wayback-Historie", toolCount: 11 },
];
