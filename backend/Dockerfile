FROM python:3.12-slim

WORKDIR /app

# System-Tools, die spätere Module (whois, dig) brauchen werden.
# Bewusst schlank gehalten -- nmap NICHT hier, das lebt im toolbox-scanner.
RUN apt-get update && apt-get install -y --no-install-recommends \
    whois \
    dnsutils \
    iputils-ping \
    traceroute \
    openssl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

RUN useradd -m -u 1000 appuser \
    && mkdir -p /data \
    && chown -R appuser:appuser /app /data
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/api/v1/health').raise_for_status()"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
