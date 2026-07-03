export type Category = {
  slug: string;
  name: string;
  description: string;
  // Wird in Phase 2+ befuellt, sobald echte Module existieren.
  toolCount: number;
};

// Struktur entspricht den im Projekt-Briefing definierten Kategorien.
// Reihenfolge = Reihenfolge in der Sidebar.
export const categories: Category[] = [
  { slug: "dns", name: "DNS", description: "Lookup, Records, Propagation", toolCount: 3 },
  { slug: "mail", name: "Mail", description: "SMTP, SPF, DKIM, DMARC", toolCount: 3 },
  { slug: "network", name: "Netzwerk", description: "Ping, Traceroute, Whois, Ports", toolCount: 4 },
  { slug: "nmap", name: "Nmap", description: "Scan-Profile, Reports", toolCount: 6 },
  { slug: "security", name: "Security", description: "SSL, Header, Score, CVE", toolCount: 5 },
  { slug: "website", name: "Website-Analyse", description: "Performance, SEO, Links", toolCount: 3 },
  { slug: "utilities", name: "Netzwerk-Utilities", description: "Rechner, Konverter, Generatoren", toolCount: 7 },
  { slug: "certificates", name: "Zertifikate", description: "SSL-Ketten, Ablauf, OCSP", toolCount: 2 },
];
