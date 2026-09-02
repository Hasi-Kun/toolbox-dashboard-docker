export type CheatsheetExample = {
  command: string;
  description: string;
};

export type CheatsheetEntry = {
  slug: string;
  name: string;
  tagline: string;
  examples: CheatsheetExample[];
};

export type CheatsheetCategory = {
  slug: string;
  name: string;
  tools: CheatsheetEntry[];
};

export const cheatsheetCategories: CheatsheetCategory[] = [
  {
    slug: "dns-network",
    name: "DNS & Netzwerk-Recon",
    tools: [
      {
        slug: "dig",
        name: "dig",
        tagline: "Maechtiger als nslookup, saubere Ausgabe, ideal fuer DNS-Debugging",
        examples: [
          { command: "dig example.com", description: "A-Record abfragen" },
          { command: "dig example.com MX", description: "Spezifischen Record-Typ abfragen" },
          { command: "dig +short example.com", description: "Nur die Antwort, ohne Zusatzausgabe" },
          { command: "dig @1.1.1.1 example.com", description: "Bestimmten Nameserver direkt befragen" },
          { command: "dig +trace example.com", description: "Kompletten Aufloesungspfad ab den Root-Servern verfolgen" },
          { command: "dig -x 8.8.8.8", description: "Reverse-Lookup (PTR-Record)" },
          { command: "dig example.com AXFR @ns1.example.com", description: "Zone-Transfer versuchen (nur bei fehlkonfiguriertem Server erfolgreich)" },
        ],
      },
      {
        slug: "host",
        name: "host",
        tagline: "Schneller, einfacherer DNS-Lookup",
        examples: [
          { command: "host example.com", description: "A/AAAA-Records auf einen Blick" },
          { command: "host -t MX example.com", description: "Bestimmten Record-Typ abfragen" },
          { command: "host -a example.com", description: "Alle verfuegbaren Records (ANY-Query)" },
        ],
      },
      {
        slug: "whois",
        name: "whois",
        tagline: "Domain-/IP-Registrierungsdaten",
        examples: [
          { command: "whois example.com", description: "Registrierungsdaten einer Domain" },
          { command: "whois 8.8.8.8", description: "Registrierungsdaten (ASN/Netzblock) einer IP" },
          { command: "whois -h whois.radb.net 8.8.8.8", description: "Gegen einen bestimmten WHOIS-Server abfragen" },
        ],
      },
      {
        slug: "traceroute-mtr",
        name: "traceroute / mtr",
        tagline: "Routing-Pfad und Latenz je Hop",
        examples: [
          { command: "traceroute example.com", description: "Routing-Pfad zum Ziel anzeigen" },
          { command: "traceroute -I example.com", description: "ICMP statt UDP nutzen (oft weniger blockiert)" },
          { command: "mtr example.com", description: "Traceroute + fortlaufendes Ping je Hop (interaktiv)" },
          { command: "mtr -rw example.com", description: "Report-Modus, einmaliger Durchlauf (skriptbar)" },
        ],
      },
      {
        slug: "ping-fping",
        name: "ping / fping",
        tagline: "Erreichbarkeit pruefen",
        examples: [
          { command: "ping -c 4 example.com", description: "4 ICMP-Pakete senden und beenden" },
          { command: "fping -a -g 192.168.1.0/24", description: "Ganzen Netzbereich auf Erreichbarkeit pruefen" },
        ],
      },
      {
        slug: "ip-ifconfig",
        name: "ip / ifconfig",
        tagline: "Interface- und Routing-Konfiguration",
        examples: [
          { command: "ip addr show", description: "Alle Interfaces und IP-Adressen anzeigen" },
          { command: "ip route show", description: "Routing-Tabelle anzeigen" },
          { command: "ip link set eth0 up", description: "Interface aktivieren" },
        ],
      },
      {
        slug: "arp",
        name: "arp / ip neigh",
        tagline: "ARP-Tabelle einsehen",
        examples: [
          { command: "ip neigh show", description: "Aktuelle ARP-/Neighbor-Tabelle anzeigen" },
          { command: "arp -a", description: "ARP-Tabelle (aeltere Syntax)" },
        ],
      },
    ],
  },
  {
    slug: "port-scanning",
    name: "Port-Scanning & Enumeration",
    tools: [
      {
        slug: "nmap",
        name: "nmap",
        tagline: "Port-Scan, Service-/OS-Detection, NSE-Skripte",
        examples: [
          { command: "nmap -sV -p- example.com", description: "Alle 65535 Ports mit Service-Erkennung (langsam, gruendlich)" },
          { command: "nmap -F example.com", description: "Schneller Scan der 100 gaengigsten Ports" },
          { command: "nmap -A example.com", description: "OS-Erkennung, Service-Version, Skripte, Traceroute kombiniert" },
          { command: "nmap -sU -p 53,123,161 example.com", description: "Bestimmte UDP-Ports pruefen" },
          { command: "nmap --script vuln example.com", description: "NSE-Skripte fuer bekannte Schwachstellen" },
          { command: "nmap -Pn example.com", description: "Host-Discovery ueberspringen (bei blockiertem Ping)" },
        ],
      },
      {
        slug: "masscan",
        name: "masscan",
        tagline: "Sehr schneller Scanner fuer grosse Adressbereiche",
        examples: [
          { command: "masscan 10.0.0.0/8 -p443 --rate 1000", description: "Ganzen /8-Bereich auf Port 443 scannen, gedrosselte Rate" },
          { command: "masscan -p1-65535 192.168.1.0/24 --rate 10000", description: "Alle Ports in einem /24 scannen" },
        ],
      },
      {
        slug: "netcat",
        name: "netcat (nc)",
        tagline: "Verbindungen testen, Banner-Grabbing, einfache Listener",
        examples: [
          { command: "nc -zv example.com 443", description: "Einzelnen Port auf Erreichbarkeit pruefen" },
          { command: "nc -zv example.com 20-25", description: "Portbereich durchtesten" },
          { command: "echo | nc example.com 80", description: "Banner/Antwort eines Dienstes abgreifen" },
          { command: "nc -lvp 4444", description: "Lokalen Listener auf Port 4444 starten (nur eigene/autorisierte Tests)" },
        ],
      },
    ],
  },
  {
    slug: "http-web",
    name: "HTTP & Web",
    tools: [
      {
        slug: "curl",
        name: "curl",
        tagline: "HTTP-Anfragen von der Kommandozeile",
        examples: [
          { command: "curl -I https://example.com", description: "Nur Response-Header abrufen" },
          { command: "curl -sL https://example.com", description: "Redirects folgen, still (keine Fortschrittsanzeige)" },
          { command: "curl -X POST -d 'key=value' https://example.com/api", description: "POST-Request mit Formulardaten" },
          { command: "curl -H 'Authorization: Bearer TOKEN' https://example.com/api", description: "Custom-Header setzen" },
          { command: "curl -v https://example.com", description: "Vollstaendigen Request/Response inkl. TLS-Handshake anzeigen" },
          { command: "curl -o datei.zip https://example.com/datei.zip", description: "In Datei speichern statt auf stdout" },
        ],
      },
      {
        slug: "wget",
        name: "wget",
        tagline: "Dateien/Seiten herunterladen",
        examples: [
          { command: "wget https://example.com/datei.zip", description: "Datei herunterladen" },
          { command: "wget -r -l2 https://example.com", description: "Rekursiv 2 Ebenen tief spiegeln" },
          { command: "wget --spider https://example.com", description: "Nur pruefen ob erreichbar, nichts herunterladen" },
        ],
      },
      {
        slug: "httpie",
        name: "httpie",
        tagline: "Benutzerfreundlichere Alternative zu curl",
        examples: [
          { command: "http GET example.com", description: "Einfacher GET-Request mit formatierter Ausgabe" },
          { command: "http POST example.com/api key=value", description: "POST mit JSON-Body (automatisch)" },
          { command: "http example.com Authorization:'Bearer TOKEN'", description: "Custom-Header setzen" },
        ],
      },
      {
        slug: "content-discovery",
        name: "gobuster / ffuf / dirb",
        tagline: "Verzeichnis-/Content-Discovery",
        examples: [
          { command: "gobuster dir -u https://example.com -w wordlist.txt", description: "Verzeichnisse/Dateien anhand einer Wortliste suchen" },
          { command: "ffuf -u https://example.com/FUZZ -w wordlist.txt", description: "Flexibles Fuzzing mit FUZZ-Platzhalter" },
          { command: "dirb https://example.com", description: "Einfacher, klassischer Verzeichnis-Scan mit Standard-Wortliste" },
        ],
      },
      {
        slug: "nikto",
        name: "nikto",
        tagline: "Webserver-Schwachstellen-Scan",
        examples: [
          { command: "nikto -h https://example.com", description: "Standard-Scan gegen einen Webserver" },
          { command: "nikto -h example.com -p 80,443", description: "Mehrere Ports pruefen" },
        ],
      },
      {
        slug: "wpscan",
        name: "wpscan",
        tagline: "WordPress-spezifischer Scanner",
        examples: [
          { command: "wpscan --url https://example.com", description: "Grundlegender WordPress-Scan (Version, Theme, Plugins)" },
          { command: "wpscan --url https://example.com --enumerate vp", description: "Nur verwundbare Plugins auflisten" },
        ],
      },
    ],
  },
  {
    slug: "packet-analysis",
    name: "Packet-Analyse",
    tools: [
      {
        slug: "tcpdump",
        name: "tcpdump",
        tagline: "CLI-Paketmitschnitt mit maechtigen Filtern",
        examples: [
          { command: "tcpdump -i eth0", description: "Live-Mitschnitt auf einem Interface" },
          { command: "tcpdump -i eth0 port 443", description: "Nur Traffic auf Port 443" },
          { command: "tcpdump -i eth0 -w mitschnitt.pcap", description: "In Datei schreiben (spaeter in Wireshark oeffnen)" },
          { command: "tcpdump -i eth0 host 10.0.0.5", description: "Nur Traffic von/zu einer bestimmten IP" },
          { command: "tcpdump -A -i eth0 port 80", description: "Paketinhalt als ASCII mitlesen" },
        ],
      },
      {
        slug: "tshark",
        name: "tshark",
        tagline: "Wireshark auf der Kommandozeile",
        examples: [
          { command: "tshark -i eth0", description: "Live-Mitschnitt mit Wireshark-Dissektoren" },
          { command: "tshark -r mitschnitt.pcap -Y 'http'", description: "Aufgezeichnete Datei nach HTTP filtern" },
        ],
      },
      {
        slug: "ngrep",
        name: "ngrep",
        tagline: "grep fuer Netzwerkverkehr",
        examples: [
          { command: "ngrep -d eth0 'GET' tcp port 80", description: "Nach 'GET' im Traffic auf Port 80 suchen" },
        ],
      },
    ],
  },
  {
    slug: "tls-crypto",
    name: "TLS / Zertifikate / Krypto",
    tools: [
      {
        slug: "openssl",
        name: "openssl",
        tagline: "Zertifikate pruefen, Verbindungen testen, Hashes -- extrem vielseitig",
        examples: [
          { command: "openssl s_client -connect example.com:443", description: "TLS-Verbindung aufbauen und Zertifikatskette anzeigen" },
          { command: "openssl x509 -in cert.pem -noout -text", description: "Zertifikat im Detail anzeigen" },
          { command: "openssl x509 -in cert.pem -noout -dates", description: "Nur Gueltigkeitszeitraum anzeigen" },
          { command: "openssl req -new -newkey rsa:2048 -nodes -keyout key.pem -out csr.pem", description: "Neuen Schluessel + CSR erzeugen" },
          { command: "openssl dgst -sha256 datei.txt", description: "SHA-256-Hash einer Datei berechnen" },
          { command: "openssl rand -hex 32", description: "Kryptographisch zufaellige Hex-Zeichenfolge erzeugen" },
        ],
      },
      {
        slug: "sslscan-testssl",
        name: "sslscan / testssl.sh",
        tagline: "TLS-Konfiguration und unterstuetzte Cipher pruefen",
        examples: [
          { command: "sslscan example.com:443", description: "Unterstuetzte Protokolle/Cipher auflisten" },
          { command: "testssl.sh example.com", description: "Gruendlicher TLS/SSL-Schwachstellen-Scan (auch als Tool in dieser Toolbox verfuegbar)" },
        ],
      },
    ],
  },
  {
    slug: "system-logs",
    name: "System, Prozesse & Logs",
    tools: [
      {
        slug: "ss-netstat",
        name: "ss / netstat",
        tagline: "Offene Ports und aktive Verbindungen",
        examples: [
          { command: "ss -tulpn", description: "Alle lauschenden TCP/UDP-Ports mit Prozess-ID" },
          { command: "ss -tan state established", description: "Nur aktive TCP-Verbindungen" },
          { command: "netstat -tulpn", description: "Aeltere Syntax, gleiche Grundidee" },
        ],
      },
      {
        slug: "lsof",
        name: "lsof",
        tagline: "Offene Dateien/Sockets pro Prozess",
        examples: [
          { command: "lsof -i :443", description: "Welcher Prozess belegt Port 443" },
          { command: "lsof -p 1234", description: "Alle offenen Dateien/Sockets eines Prozesses (PID)" },
        ],
      },
      {
        slug: "journalctl",
        name: "journalctl",
        tagline: "systemd-Logs durchsuchen",
        examples: [
          { command: "journalctl -u nginx -f", description: "Logs eines Diensts live mitverfolgen" },
          { command: "journalctl --since '1 hour ago'", description: "Logs der letzten Stunde" },
          { command: "journalctl -p err", description: "Nur Fehler-Meldungen" },
        ],
      },
      {
        slug: "text-processing",
        name: "grep / awk / sed / jq",
        tagline: "Log- und Text-/JSON-Verarbeitung",
        examples: [
          { command: "grep -i 'error' log.txt", description: "Zeilen mit 'error' finden (gross-/kleinschreibungsunabhaengig)" },
          { command: "awk '{print $1}' log.txt", description: "Erste Spalte jeder Zeile ausgeben" },
          { command: "sed 's/alt/neu/g' datei.txt", description: "Text ersetzen" },
          { command: "curl -s api.example.com | jq '.data[]'", description: "JSON-Antwort strukturiert durchsuchen" },
        ],
      },
    ],
  },
  {
    slug: "hashing-forensics",
    name: "Hashing, Passwoerter & Forensik",
    tools: [
      {
        slug: "hashcat-john",
        name: "hashcat / john",
        tagline: "Passwort-Audits (nur fuer legitime, autorisierte Pruefungen)",
        examples: [
          { command: "hashcat -m 0 -a 0 hashes.txt wordlist.txt", description: "MD5-Hashes gegen eine Wortliste pruefen" },
          { command: "john --wordlist=wordlist.txt hashes.txt", description: "John the Ripper mit Wortliste" },
          { command: "john --show hashes.txt", description: "Bereits geknackte Hashes anzeigen" },
        ],
      },
      {
        slug: "checksums",
        name: "sha256sum / md5sum",
        tagline: "Integritaetspruefung von Dateien",
        examples: [
          { command: "sha256sum datei.iso", description: "SHA-256-Pruefsumme berechnen" },
          { command: "sha256sum -c pruefsummen.txt", description: "Gegen eine Liste bekannter Pruefsummen verifizieren" },
        ],
      },
      {
        slug: "file-inspection",
        name: "strings / xxd / file",
        tagline: "Datei-/Binary-Inspektion",
        examples: [
          { command: "strings binary | less", description: "Lesbaren Text in einer Binaerdatei finden" },
          { command: "xxd datei.bin | head", description: "Hexdump der ersten Bytes" },
          { command: "file datei.unbekannt", description: "Tatsaechlichen Dateityp anhand Magic Bytes bestimmen" },
        ],
      },
      {
        slug: "steghide-exiftool",
        name: "steghide / exiftool",
        tagline: "Metadaten und Steganografie",
        examples: [
          { command: "exiftool bild.jpg", description: "Alle Metadaten einer Datei anzeigen" },
          { command: "exiftool -all= bild.jpg", description: "Metadaten entfernen" },
          { command: "steghide info bild.jpg", description: "Pruefen ob versteckte Daten eingebettet sind" },
        ],
      },
    ],
  },
  {
    slug: "misc",
    name: "Weiteres Nuetzliches",
    tools: [
      {
        slug: "ssh-scp",
        name: "ssh / scp",
        tagline: "Zugriff und Dateitransfer",
        examples: [
          { command: "ssh user@example.com", description: "Verbinden" },
          { command: "ssh -i key.pem user@example.com", description: "Mit privatem Schluessel verbinden" },
          { command: "scp datei.txt user@example.com:/pfad/", description: "Datei hochladen" },
          { command: "ssh -L 8080:localhost:80 user@example.com", description: "Lokales Port-Forwarding (Tunnel)" },
        ],
      },
      {
        slug: "git",
        name: "git",
        tagline: "Versionierung -- auch fuer Config-/IaC-Audits nuetzlich",
        examples: [
          { command: "git log --oneline -20", description: "Letzte 20 Commits kompakt anzeigen" },
          { command: "git diff HEAD~1", description: "Aenderungen seit dem vorletzten Commit" },
          { command: "git log -p --follow -- pfad/datei", description: "Komplette Historie einer Datei inkl. Umbenennungen" },
        ],
      },
      {
        slug: "nuclei",
        name: "nuclei",
        tagline: "Templatebasiertes Vulnerability-Scanning",
        examples: [
          { command: "nuclei -u https://example.com", description: "Standard-Templates gegen ein Ziel laufen lassen" },
          { command: "nuclei -u https://example.com -severity critical,high", description: "Nur nach kritischen/hohen Befunden suchen" },
        ],
      },
      {
        slug: "hydra",
        name: "hydra",
        tagline: "Login-Brute-Force -- ausschliesslich fuer autorisierte Tests am eigenen/freigegebenen Zielsystem",
        examples: [
          { command: "hydra -l admin -P wordlist.txt ssh://example.com", description: "SSH-Login mit einer Wortliste testen (nur mit ausdruecklicher Erlaubnis)" },
        ],
      },
    ],
  },
];
