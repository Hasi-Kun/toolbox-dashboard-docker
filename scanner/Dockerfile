FROM python:3.12-slim

WORKDIR /app

# nmap + libcap2-bin (fuer setcap) + Perl-Abhaengigkeiten fuer Nikto.
# Nikto selbst kommt per Git-Clone (siehe unten), NICHT ueber apt --
# das Debian-Paket liegt im 'non-free'-Repo, das im schlanken Basis-Image
# nicht aktiviert ist. Nikto ist reines Perl, braucht nur die Perl-
# Module hier + git zum Holen des Scripts selbst.
#
# libxml-writer-perl ist die einzige report-format-spezifische
# Abhaengigkeit, die wir noch brauchen -- Nikto wird ueber XML- statt
# JSON-Ausgabe angesteuert (siehe nikto_parser.py fuer die ausfuehrliche
# Begruendung: Niktos JSON-Report-Plugin hat sich in dieser Umgebung
# wiederholt als nicht funktionsfaehig erwiesen, vermutlich ein Bug in
# Nikto 2.5.0 selbst -- https://github.com/sullo/nikto/issues/793).
#
# bsdextrautils (hexdump), procps (ps) und dnsutils (dig/host/nslookup)
# sind testssl.sh-Abhaengigkeiten, die im schlanken Basis-Image FEHLEN
# und beim Start mit "Fatal error: you need to install X" abbrechen --
# per bekanntem Debian-Bugreport (#962995) und Upstream-Issue #2541
# VORAB alle drei ergaenzt, statt einzeln nacheinander zu entdecken.
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    libcap2-bin \
    git \
    perl \
    libnet-ssleay-perl \
    libio-socket-ssl-perl \
    libwhisker2-perl \
    libxml-writer-perl \
    bsdextrautils \
    procps \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Build-Selbsttest: reproduziert den Aufruf, den Niktos XML-Report-Plugin
# intern nutzt (XML::Writer->new). Schlaegt das hier fehl, bricht der
# DOCKER-BUILD SOFORT ab -- mit der praezisen Perl-Fehlermeldung direkt
# im Build-Log, statt erst nach dem Deploy beim ersten echten Scan-
# Versuch aufzufallen.
RUN perl -e 'use XML::Writer; my $w = XML::Writer->new(OUTPUT => "self"); print "[Build-Selbsttest] XML::Writer funktioniert: " . ref($w) . "\n";'

# Nikto in einer festen, ueberprueften Version klonen (kein "latest" --
# reproduzierbare Builds, keine ueberraschenden Aenderungen beim Rebuild).
RUN git clone --depth 1 --branch 2.5.0 https://github.com/sullo/nikto.git /opt/nikto \
    && chmod +x /opt/nikto/program/nikto.pl \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto

# Zweiter, spezifischerer Build-Selbsttest: syntax-prueft das XML-Report-
# Plugin direkt (das jetzt tatsaechlich verwendete Ausgabeformat).
RUN perl -c /opt/nikto/program/plugins/nikto_report_xml.plugin

# testssl.sh (drwetter/testssl.sh) -- gruendlicher TLS/SSL-Pruefer, der
# gezielt auf bekannte Schwachstellen testet (Heartbleed, POODLE, ROBOT,
# DROWN, LOGJAM, Ticketbleed, CCS-Injection, BEAST, FREAK, LUCKY13,
# SWEET32, u.a.) -- deutlich gruendlicher als unser eigenes
# tls-cipher-audit. Reines Bash-Script (kein Python/Perl-Aequivalent zu
# Niktos Problemen), braucht nur bash + openssl (beide bereits im
# Basis-Image). Feste, ueberpruefte Version statt "latest".
RUN git clone --depth 1 --branch v3.2.3 https://github.com/testssl/testssl.sh.git /opt/testssl \
    && chmod +x /opt/testssl/testssl.sh \
    && ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh

# Build-Selbsttest: prueft explizit auf die drei bekannten "versteckten"
# Abhaengigkeiten (siehe Kommentar oben), BEVOR testssl.sh selbst
# aufgerufen wird -- so zeigt ein fehlender Befehl sofort seinen eigenen
# Namen im Build-Log, statt nur testssl.sh's generischer Fehlermeldung.
RUN command -v hexdump && command -v ps && command -v dig && echo "[Build-Selbsttest] hexdump/ps/dig sind vorhanden"

# Build-Selbsttest: --help muss sauber durchlaufen (prueft, dass Bash-
# Sockets/OpenSSL-Aufrufe grundsaetzlich funktionieren, ohne dafuer schon
# einen echten Netzwerk-Scan zu brauchen).
RUN /opt/testssl/testssl.sh --help > /dev/null && echo "[Build-Selbsttest] testssl.sh --help laeuft durch"

# Datei-Capabilities auf das nmap-Binary selbst -- dadurch kann nmap Raw
# Sockets nutzen (SYN-Scans, OS-Detection), OHNE dass der Prozess als root
# laeuft. Die Kernel-Faehigkeit kommt zusaetzlich aus docker-compose.yml
# (cap_add: NET_RAW, NET_ADMIN) -- beides zusammen ist noetig.
RUN setcap cap_net_raw,cap_net_admin+eip $(which nmap)

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

RUN useradd -m -u 1000 scanneruser && chown -R scanneruser:scanneruser /app /opt/nikto /opt/testssl
USER scanneruser

# Nmap prueft standardmaessig geteuid()==0 fuer privilegierte Scans --
# diese Variable sagt ihm, dass die Kernel-Capabilities (siehe oben)
# bereits ausreichen, auch ohne echten root.
ENV NMAP_PRIVILEGED=1

CMD ["python", "-m", "app.worker"]
