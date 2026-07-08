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
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    libcap2-bin \
    git \
    perl \
    libnet-ssleay-perl \
    libio-socket-ssl-perl \
    libwhisker2-perl \
    libxml-writer-perl \
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

# Datei-Capabilities auf das nmap-Binary selbst -- dadurch kann nmap Raw
# Sockets nutzen (SYN-Scans, OS-Detection), OHNE dass der Prozess als root
# laeuft. Die Kernel-Faehigkeit kommt zusaetzlich aus docker-compose.yml
# (cap_add: NET_RAW, NET_ADMIN) -- beides zusammen ist noetig.
RUN setcap cap_net_raw,cap_net_admin+eip $(which nmap)

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

RUN useradd -m -u 1000 scanneruser && chown -R scanneruser:scanneruser /app /opt/nikto
USER scanneruser

# Nmap prueft standardmaessig geteuid()==0 fuer privilegierte Scans --
# diese Variable sagt ihm, dass die Kernel-Capabilities (siehe oben)
# bereits ausreichen, auch ohne echten root.
ENV NMAP_PRIVILEGED=1

CMD ["python", "-m", "app.worker"]
