# Toolbox Dashboard

Self-hosted modular dashboard application (Next.js + Docker).

## Requirements

* Linux server (Debian 12 / Ubuntu 24.04 recommended)
* Docker + Docker Compose
* Caddy reverse proxy
* Domain pointing to the server

---

## Installation

```bash
unzip -o toolbox-dashboard-i18n.zip
docker compose up -d --build
```

---

## Reverse Proxy (Caddy)

The application is designed to run behind Caddy as reverse proxy with automatic HTTPS.

### Example Docker Compose (Caddy)

```yaml
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

### Example Caddyfile

```caddy
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

sub.domain.tld {
    handle /.well-known/acme-challenge/* {
        root * /srv/security
        file_server
    }

    handle {
        import block_common
        reverse_proxy toolbox-frontend:3000
    }

    import headers_common
}
```

Replace:

* `sub.domain.tld` with your domain
* `toolbox-frontend` with your container name if different

---

## Notes

* All services run via Docker Compose
* Caddy handles HTTPS automatically (Let’s Encrypt)
* No additional setup required after `docker compose up -d --build`
* Ensure the Docker network `webnet` exists before starting services

```bash
docker network create webnet
```
