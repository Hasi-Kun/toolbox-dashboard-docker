FROM python:3.12-slim

WORKDIR /app

# nmap + libcap2-bin (fuer setcap) + Perl-Abhaengigkeiten fuer Nikto.
# Nikto selbst kommt per Git-Clone (siehe unten), NICHT ueber apt --
# das Debian-Paket liegt im 'non-free'-Repo, das im schlanken Basis-Image
# nicht aktiviert ist. Nikto ist reines Perl, braucht nur die Perl-
# Module hier + git zum Holen des Scripts selbst.
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    libcap2-bin \
    git \
    perl \
    libnet-ssleay-perl \
    libio-socket-ssl-perl \
    libwhisker2-perl \
    libjson-pp-perl \
    libxml-writer-perl \
    && rm -rf /var/lib/apt/lists/*

# Nikto in einer festen, ueberprueften Version klonen (kein "latest" --
# reproduzierbare Builds, keine ueberraschenden Aenderungen beim Rebuild).
RUN git clone --depth 1 --branch 2.5.0 https://github.com/sullo/nikto.git /opt/nikto \
    && chmod +x /opt/nikto/program/nikto.pl \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto

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
