# Toolbox Dashboard

Self-hosted modular dashboard application.

This project is **domain-template based** and supports automated deployment via install script.

<img width="1920" height="948" alt="grafik" src="https://github.com/user-attachments/assets/9b8e9284-53d9-4c43-981c-4267b8977980" />

<img width="1920" height="949" alt="grafik" src="https://github.com/user-attachments/assets/073f86e6-7100-4397-b02d-8ea2446911ac" />


---

## Requirements

* Linux server (Debian 12 / Ubuntu 24.04 recommended)
* Docker + Docker Compose
* Caddy reverse proxy
* Domain pointing to the server

---

## Installation

### Recommended (automatic setup with domain injection)

```bash id="inst1"
unzip -o toolbox-dashboard.zip
chmod +x install.sh
./install.sh example.com
```

Optional subdomain:

```bash id="inst2"
./install.sh example.com toolbox
```

This will:

* extract the project
* replace all placeholders
* configure domains
* start Docker stack

---

## Domain placeholders

The repository uses a template system (no hardcoded production domains):

```env id="envtpl"
WEBAUTHN_RP_ID=toolbox.domain.cc
WEBAUTHN_RP_NAME=Toolbox
WEBAUTHN_ORIGIN=https://toolbox.domain.cc
```

These values are automatically replaced during installation:

| Placeholder       | Example             |
| ----------------- | ------------------- |
| toolbox.domain.cc | toolbox.example.com |

---

## Reverse Proxy (Caddy)

The application is designed to run behind Caddy with automatic HTTPS.

### Example Docker Compose (Caddy)

```yaml id="caddy1"
services:
  caddy:
    image: caddy:latest
    container_name: caddy
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /data/caddy/Caddyfile:/etc/caddy/Caddyfile
      - /data/caddy/data:/data
      - /data/caddy/config:/config
      - /data/caddy/logs:/var/log/caddy
      - /data/security:/srv/security
    restart: unless-stopped
    networks:
      - webnet

networks:
  webnet:
    external: true
```

---

### Example Caddyfile

```caddy id="caddy2"
(block_common) {
    @blocked {
        path /.git* /.env* /composer.* /package.json
    }
    respond @blocked 403
}

(headers_common) {
    header {
        X-Content-Type-Options "nosniff"
        Referrer-Policy ?strict-origin-when-cross-origin
        Permissions-Policy "geolocation=(), microphone=(), camera=()"
        X-Frame-Options "SAMEORIGIN"
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        -Server
        -X-Powered-By
    }
}

{{TOOLBOX_DOMAIN}} {
    handle {
        import block_common
        reverse_proxy toolbox-frontend:3000
    }

    import headers_common
}
```

---

## Notes

* Docker Compose handles full stack deployment
* Caddy provides automatic SSL (Let’s Encrypt)
* No manual configuration required after install script
* Ensure Docker network exists (auto-created by installer)

---

## Network setup (optional manual step)

If needed:

```bash id="net1"
docker network create webnet
```

---

## Important

Do not deploy directly from repository without running the installer.

All domain values are placeholders and must be replaced during setup.
