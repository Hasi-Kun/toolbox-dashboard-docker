FROM python:3.12-slim

WORKDIR /app

# nmap + libcap2-bin (fuer setcap). Bewusst NUR nmap hier -- keine anderen
# Netzwerk-Tools, dieser Container hat einen einzigen Zweck.
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# Datei-Capabilities auf das nmap-Binary selbst -- dadurch kann nmap Raw
# Sockets nutzen (SYN-Scans, OS-Detection), OHNE dass der Prozess als root
# laeuft. Die Kernel-Faehigkeit kommt zusaetzlich aus docker-compose.yml
# (cap_add: NET_RAW, NET_ADMIN) -- beides zusammen ist noetig.
RUN setcap cap_net_raw,cap_net_admin+eip $(which nmap)

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

RUN useradd -m -u 1000 scanneruser && chown -R scanneruser:scanneruser /app
USER scanneruser

# Nmap prueft standardmaessig geteuid()==0 fuer privilegierte Scans --
# diese Variable sagt ihm, dass die Kernel-Capabilities (siehe oben)
# bereits ausreichen, auch ohne echten root.
ENV NMAP_PRIVILEGED=1

CMD ["python", "-m", "app.worker"]
