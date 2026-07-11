# Caddy-Integration

Kein zweiter Reverse Proxy nötig. Füge in deiner bestehenden
`/data/caddy/Caddyfile` einfach folgenden Host-Block zu den anderen Hosts
hinzu (gleiche Struktur wie `bookstack.{{BASE_DOMAIN}}`):

```caddyfile
{{TOOLBOX_DOMAIN}} {
    handle /.well-known/acme-challenge/* {
        root * /srv/security
        file_server
    }
    handle {
        import block_common
        reverse_proxy toolbox-frontend:3000 {
            header_up X-Real-IP {http.request.header.CF-Connecting-IP}
            transport http {
                read_timeout 320s
                write_timeout 320s
            }
        }
    }
    import headers_common
}
```

**WICHTIG -- Timeout auf 320s erhoeht (Update):** Die aktiven Scan-Tools
(nmap-full-port-scan, nmap-vuln-scan, Nikto) koennen je nach Ziel bis zu
300 Sekunden dauern. Mit dem alten `120s`-Timeout hat Caddy die Verbindung
GEKAPPT, bevor das Backend fertig antworten konnte -- der Browser bekam
dadurch eine abgeschnittene/unvollstaendige Antwort statt sauberem JSON
(Symptom: "JSON.parse: unexpected character..." im Frontend, OHNE
jeglichen Fehler im Backend-Log, weil das Backend zu dem Zeitpunkt noch
gar nicht fertig war). Nach dem Aendern **`caddy reload`** nicht vergessen.

**Cloudflare-Falle (falls die Domain per oranger Wolke proxied ist):**
Cloudflares eigener Edge-Proxy hat auf Free/Pro-Tarifen ein eigenes,
separates Timeout fuer proxied HTTP-Verbindungen -- typischerweise um die
100 Sekunden, unabhaengig davon, was Caddy dahinter erlaubt. Selbst mit
dem obigen Caddy-Fix koennte ein Scan, der laenger als ~100s dauert,
also IMMER NOCH an Cloudflares eigenem Timeout scheitern, BEVOR die
Anfrage ueberhaupt bei Caddy ankommt. Zwei Wege, das zu umgehen:
1. Fuer `{{TOOLBOX_DOMAIN}}` (oder eine dedizierte Sub-Subdomain nur fuer
   die Scan-Tools) die Cloudflare-Proxy-Funktion deaktivieren ("DNS only",
   graue statt orange Wolke) -- dann greift nur noch Caddys eigenes Timeout.
2. Die Scan-Tools im Frontend auf ein Polling-Muster umstellen (Scan
   anstossen -> sofort eine Job-ID zurueckbekommen -> Ergebnis per
   kurzen, wiederholten Anfragen abfragen) statt eine einzelne, lange
   offene HTTP-Anfrage zu halten -- damit ist JEDE einzelne Anfrage kurz
   und unempfindlich gegen Timeouts jeglicher Art (Cloudflare, Caddy,
   Browser). Das waere die sauberere Langfrist-Loesung, aber ein
   groesserer Umbau -- sag Bescheid, falls du das umgesetzt haben willst,
   falls die Cloudflare-Grenze nach dem einfachen Fix wirklich noch zuschlaegt.

**Wichtig zur IP-Weitergabe:** `{{TOOLBOX_DOMAIN}}` laeuft hinter Cloudflare
(orange Wolke). `{remote_host}` wuerde in diesem Fall nur Cloudflares
eigene Edge-IP liefern, nicht die echte Besucher-IP -- deshalb wird
stattdessen `CF-Connecting-IP` verwendet, ein von Cloudflare selbst
gesetzter Header, der immer die tatsaechliche Client-IP enthaelt,
unabhaengig davon, wie viele Proxies dazwischen haengen. Falls die Domain
NICHT ueber Cloudflare laeuft, `{http.request.header.CF-Connecting-IP}`
durch `{remote_host}` ersetzen.

Damit erscheint im Backend-Log (`docker compose logs toolbox-backend`) die
echte Besucher-IP statt einer internen Docker-IP, inklusive Zeitstempel
und Antwortzeit -- z.B.:
```
2026-07-05 20:14:03,112 | INFO | toolbox.access | 203.0.113.42 GET /api/v1/tools -> 200 (12.3ms)
```

**So pruefst du, ob es wirklich ankommt:** Nach dem Speichern der
Caddyfile `caddy reload` (oder den Caddy-Container/-Service neu starten,
je nach Setup) nicht vergessen -- eine reine Datei-Aenderung wird sonst
nie aktiv. Dann einmal die Toolbox aufrufen und direkt danach
```
docker compose logs --tail=20 toolbox-backend
```
pruefen: steht dort eine echte oeffentliche IP (z.B. `203.0.113.42`)
oder weiterhin eine interne Docker-IP (z.B. `172.2x.x.x`)? Bei einer
internen IP kommt der Header nicht an -- dann `caddy reload` nochmal
pruefen bzw. die Caddyfile-Syntax kontrollieren.

**Zusaetzliche Absicherung im Code:** Das Backend prueft mittlerweile
nicht nur `X-Real-IP`, sondern faellt automatisch auf `CF-Connecting-IP`
und `X-Forwarded-For` zurueck, falls einer davon gesetzt ist (Caddy setzt
`X-Forwarded-For` bei `reverse_proxy` standardmaessig ohnehin automatisch,
auch ganz ohne die obige `header_up`-Zeile). Die explizite `header_up
X-Real-IP`-Zeile bleibt trotzdem empfohlen, da sie am zuverlaessigsten
die echte Cloudflare-Besucher-IP liefert.

Wichtig: `toolbox-frontend` muss im selben Docker-Netzwerk wie Caddy hängen
(`webnet`, `external: true` – siehe `docker-compose.yml` in diesem Projekt).

Danach:

```bash
docker exec caddy caddy validate --config /etc/caddy/Caddyfile
docker exec caddy caddy reload --config /etc/caddy/Caddyfile
```

## Hinweis zu Rate Limiting auf Caddy-Ebene

Da hier aktive Scan-Tools (Nmap etc.) über eine öffentliche Domain erreichbar
sein werden, ist es sinnvoll, zusätzlich zum Redis-basierten Rate Limiting im
Backend auch auf Caddy-Ebene ein Limit zu setzen, sobald das Nmap-Modul
(Phase 5) steht. Das behandeln wir dann konkret in der entsprechenden Phase.
