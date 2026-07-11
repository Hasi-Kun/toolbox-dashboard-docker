# Architektur

## Modul-Pattern (Backend)

Jedes Tool ist ein Modul mit einem einheitlichen Interface, definiert in
`app/modules/base.py`. Ein Modul besteht aus:

- `metadata` – Name, Kategorie, Beschreibung, Icon, ob es "aktiv" (scannend)
  oder "passiv" (nur lesend, z. B. DNS-Lookup) ist
- `run(input)` – die eigentliche Logik, immer async, immer mit Timeout
- `input_schema` / `output_schema` – Pydantic-Modelle für Validierung

Neue Tools werden in `app/modules/<kategorie>/<tool>.py` angelegt und beim
Start automatisch von der Registry (`app/modules/__init__.py`) eingesammelt.
Der Router muss dafür nicht angefasst werden.

## Sicherheitsprinzipien

1. **Trennung passiv/aktiv.** Passive Tools (DNS-Lookup, Whois, Header-Check)
   laufen direkt im Backend. Aktive Tools (Port-Scans, Nmap) laufen
   ausschließlich im `toolbox-scanner`-Container, angesprochen über eine
   Redis-Queue – niemals über direkten Funktionsaufruf oder Shell-Exec vom
   Hauptprozess aus.
2. **Keine Shell-Interpolation.** Alle externen Tools (nmap, whois, dig)
   werden über `asyncio.create_subprocess_exec` mit Argumenten-Listen
   aufgerufen, nie über `shell=True` oder String-Konkatenation.
3. **Eingabevalidierung.** Jedes Modul definiert ein strenges Pydantic-Schema
   (z. B. IP/CIDR/Hostname-Validatoren) – Freitext-Eingaben werden abgelehnt,
   nicht "escaped".
4. **Rate Limiting.** Pro IP und pro Modul-Kategorie über Redis, besonders
   streng für aktive Scans (Abuse-Schutz, verhindert dass dein Server als
   Ausgangspunkt für Scan-Beschwerden auffällt).
5. **Timeouts überall.** Jedes Modul bekommt ein hartes Timeout aus der
   Konfiguration; hängende Subprozesse werden gekillt, nicht "gewartet".
6. **Audit Log.** Jeder Scan/Lookup wird mit Zeitstempel, anfragender IP
   (soweit durch Caddy `X-Real-IP` weitergegeben), Modul und Zielwert
   protokolliert.

## Warum FastAPI statt NestJS

Die Kernbibliotheken für dieses Projekt (`dnspython`, `python-whois`,
`sslyze`, `python-nmap`, `cryptography`) existieren im Python-Ökosystem in
ausgereifter Form; das Node-Äquivalent wäre in vielen Fällen ein dünner
Wrapper um dieselben C-Bibliotheken oder schlicht nicht vorhanden. FastAPI
bietet zusätzlich native async-Unterstützung und automatische OpenAPI-Doku,
was für ein API-first, modulares System direkt nutzbar ist.

## Warum kein Traefik / Nginx Proxy Manager

Der Server hat bereits eine gehärtete Caddy-Konfiguration mit
Security-Headern, ACME-Automatik und Cloudflare-Trusted-Proxies für alle
anderen Dienste (Nextcloud, BookStack, Vaultwarden). Ein zweiter
Reverse-Proxy würde nur zusätzliche Angriffsfläche, Zertifikatsverwaltung
und Wartungsaufwand bedeuten, ohne funktionalen Mehrwert. `toolbox` reiht
sich stattdessen als weiterer Host-Block in die bestehende Caddyfile ein.

## Auth-Architektur

**Warum Session-Cookies statt JWT:** Ein serverseitiger Session-Store (Redis)
erlaubt sofortigen Logout und Revoke -- z.B. wenn ein Admin einen Account
deaktiviert oder 2FA zurueckgesetzt wird, ist die bestehende Session sofort
ungueltig. Ein selbst-validierendes JWT im Cookie wuerde bis zum Ablauf
weiter funktionieren, sofern keine zusaetzliche Blocklist gepflegt wird.

**Warum das Frontend als BFF (Backend-for-Frontend) fungiert:** Das Backend
haengt bewusst NICHT am `webnet`-Netzwerk und ist damit von aussen gar nicht
erreichbar -- nur `toolbox-frontend` ist es. Damit das Session-Cookie trotzdem
funktioniert, leiten die Next.js Route Handler unter `frontend/app/api/*`
Auth-Requests intern an das Backend weiter und reichen den `Set-Cookie`-Header
1:1 an den Browser durch (`lib/backend-proxy.ts`). Der Browser sieht dabei nur
eine Origin (`{{TOOLBOX_DOMAIN}}`), das Cookie ist also ganz normal same-origin.

**2FA ist zwingend, nicht optional.** Nach Passwort-Pruefung wird nie direkt
eine Session ausgestellt -- es entsteht immer erst ein "Pending-Login"-Token
in Redis (5 Minuten gueltig). Erst nach erfolgreicher TOTP- oder
Passkey-Verifikation (bzw. deren Einrichtung beim allerersten Login) wird
eine echte Session erzeugt.

**Passkey/WebAuthn-Details:** Verifikation laeuft ueber die `webauthn`-Library
serverseitig; RP-ID und Origin muessen exakt zur oeffentlichen Domain passen
(`{{TOOLBOX_DOMAIN}}` / `https://{{TOOLBOX_DOMAIN}}`). Der `sign_count` jedes
Credentials wird nach jeder Anmeldung aktualisiert -- ein Counter, der nicht
steigt, kann auf einen geklonten Authenticator hindeuten (aktuell nur
gespeichert, noch keine aktive Alarmierung darauf).

**Keine oeffentliche Registrierung.** Der erste Account entsteht per
CLI-Skript direkt im Container (`app/scripts/create_admin.py`), alle
weiteren ueber die Verwaltungsseite im Dashboard (nur fuer Rolle `admin`
erreichbar, serverseitig über `require_admin` erzwungen -- nicht nur im
Frontend versteckt).

**Rate-Limiting gegen Brute-Force:** Login- und 2FA-Verify-Endpoints haben
ein eigenes, strengeres Limit (`LOGIN_RATE_LIMIT_PER_MINUTE`, Default 10)
als die uebrigen Tool-Endpoints.

**Bekannte Grenzen dieser Phase (fuer spaetere Haertung notiert):**
- Kein "Passwort bei erstem Login aendern"-Zwang fuer per Admin generierte Passwoerter
- Kein Audit-Log fuer Login-Versuche/Admin-Aktionen (siehe allgemeine Sicherheitsprinzipien oben)
- `totp_secret` liegt nur auf Volume-Ebene, nicht zusaetzlich applikationsseitig verschluesselt

## Self-Service: Passwort und Mehrfach-2FA

Zusaetzlich zum erzwungenen Erstlogin-2FA-Setup gibt es `/settings/security`
im Dashboard fuer eingeloggte Benutzer:

- Passwort aendern (verlangt das aktuelle Passwort, rate-limited wie der Login)
- TOTP und Passkey **gleichzeitig** aktiv haben, nicht nur eines von beiden
- TOTP rotieren (neues Secret) oder deaktivieren
- Beliebig viele Passkeys hinzufuegen/entfernen (z.B. Laptop + Handy + YubiKey)

**Sicherheitsregel:** Es muss immer mindestens eine 2FA-Methode aktiv
bleiben. Der letzte Passkey kann nicht geloescht werden, wenn TOTP
deaktiviert ist (und umgekehrt) -- das wird serverseitig erzwungen
(`_remaining_factors_after` in `app/api/v1/endpoints/account.py`), nicht
nur im Frontend verhindert.

Diese Endpoints sind bewusst getrennt von den Login-Flow-Endpoints
(`/auth/2fa/...`): sie haengen an der bereits bestehenden Session
(`get_current_user`), nicht an einem `pending_token`, weil hier kein
Passwort-Check mehr noetig ist -- die Person ist ja schon angemeldet.

## Netzwerk-Module (Phase 3)

**Warum Ping/Traceroute im Haupt-Backend statt im isolierten Scanner:**
Beide sind read-only aus Netzwerksicht (ICMP Echo bzw. UDP-Traceroute gegen
genau ein vom User angegebenes Ziel), kein Sweep ueber Portbereiche. Sie
brauchen aber `CAP_NET_RAW` fuer Raw-Sockets -- das ist im
`docker-compose.yml` bewusst NUR fuer `toolbox-backend` gesetzt, kein
`--privileged`, kein root-User (der Container laeuft weiterhin als
`appuser`, siehe Dockerfile).

**Subprocess-Sicherheit:** `ping`, `traceroute`, `whois` werden ausschliesslich
ueber `asyncio.create_subprocess_exec` mit einer Argument-Liste aufgerufen
(`app/modules/network/common.py`), nie ueber eine Shell. Der Zielwert
(Hostname/IP) wird vorher ueber `is_valid_hostname`/`is_valid_ip` validiert
und landet als eigenes Argv-Element im Aufruf -- selbst wenn ein Validator
eine Luecke haette, gaebe es keine Shell, die Metazeichen interpretieren
koennte.

**Port-Check ist bewusst kein Scanner:** Maximal 10 explizit angegebene
Ports pro Anfrage, jeweils ein einzelner TCP-Connect-Versuch mit 3s Timeout.
Fuer echtes Port-Scanning (Portbereiche, Service-Detection, aggressive
Scans) bleibt es bei der geplanten Isolation in Phase 5 (`toolbox-scanner`,
`is_active_scan=True`, aktuell noch 501).

## Security-Module (Phase 4)

**SSL Checker liest auch "kaputte" Zertifikate aus.** Standardmaessig
verweigert Pythons `ssl`-Modul den Zugriff auf Zertifikatsdetails, wenn die
Verifikation fehlschlaegt (abgelaufen, selbstsigniert, falscher Hostname).
Das ist fuer einen Checker unbrauchbar -- genau diese Faelle will man ja
sehen. Deshalb: eine unverifizierte Verbindung liest das Rohzertifikat
(`getpeercert(binary_form=True)` + `cryptography.x509`), eine zweite,
echte Verifikation bestimmt separat das `trusted`-Flag. So gibt es immer
Zertifikatsdetails, aber auch eine ehrliche Aussage, ob ein Standard-
Trust-Store dem Zertifikat vertrauen wuerde.

**Security-Header-Score ist bewusst simpel gehalten.** Sechs gepruefte
Header mit fester Gewichtung, keine externen Abhaengigkeiten. Das deckt
die haeufigsten Findings ab (fehlende HSTS/CSP sind die grossen
Klassiker), ist aber kein Ersatz fuer Tools wie Mozilla Observatory bei
tieferer Analyse (z.B. CSP-Direktiven-Qualitaet).

**robots.txt/security.txt-Parser sind bewusst tolerant.** Kommentare
(`#`) werden ignoriert, unbekannte Felder einfach uebersprungen statt
Fehler zu werfen -- beide Dateien werden in der Praxis oft von Hand
gepflegt und sind nicht immer strikt spezifikationskonform.

## Bekannte Luecke: Kategorie-Seiten (behoben in Phase 4)

Die Dashboard-Kacheln und die Sidebar haben von Anfang an auf
`/category/[slug]` verlinkt, aber diese Route wurde nie gebaut (nur die
Startseite existierte). Das fiel erst durch eine echte Browser-Session auf
(404). Seither gibt es `frontend/app/category/[slug]/page.tsx`, die die
Module der jeweiligen Kategorie live vom Backend laedt.

## Nmap-Integration im isolierten Scanner (Phase 5)

**Warum ein eigener Container statt Nmap im Backend.** Nmap braucht
Raw-Sockets (`CAP_NET_RAW`, fuer OS-Detection zusaetzlich `CAP_NET_ADMIN`).
Diese Capabilities NUR fuer den Scanner-Container zu vergeben -- und
niemals fuer `toolbox-backend` -- begrenzt den Schaden, falls in einem der
beiden Container jemals eine Schwachstelle ausgenutzt wird. Der Scanner hat
zudem keinerlei Zugriff auf `webnet` oder die Datenbank; selbst ein
kompromittierter Scanner-Container koennte also weder das Internet direkt
erreichen (ausser fuer die eigentlichen Scans) noch an Nutzerdaten kommen.

**Kommunikation ausschliesslich ueber Redis-Queue, kein direkter Kontakt.**
Backend und Scanner sprechen nie direkt miteinander -- das Backend legt
Jobs in eine Liste (`scanner:jobs`), der Scanner nimmt sie per `BLPOP`
und schreibt Ergebnisse unter `scanner:result:{job_id}` mit TTL zurueck.
Das Backend pollt auf das Ergebnis. Kein offener Port zwischen den beiden,
keine RPC-Bibliothek, keine gemeinsame Codebasis (bewusste Duplikation der
Zielvalidierung im Scanner, siehe `scanner/app/common.py`).

**Fixe Templates statt freier Flags -- der zentrale Sicherheitsmechanismus.**
`scanner/app/templates.py` definiert genau sechs feste nmap-Aufrufe. Ein
Job traegt nur `template` (ein Name aus dieser festen Liste) und `params`
(Ziel, ggf. Portzahl/-liste) -- niemals rohe nmap-Argumente. Selbst wenn
irgendwo in der Kette Nutzereingaben durchrutschen wuerden, gibt es keinen
Pfad, ueber den sie zu nmap-Kommandozeilenflags werden koennten.

**`NMAP_PRIVILEGED=1` ist kein Sicherheitsfeature, sondern noetig fuer
Funktionalitaet.** Nmap prueft standardmaessig die effektive UID und
verweigert privilegierte Scans, wenn sie nicht 0 ist -- unabhaengig davon,
ob der Prozess tatsaechlich die noetigen Kernel-Capabilities hat. Diese
Env-Var sagt nmap, die eigene UID-Pruefung zu ueberspringen; die
tatsaechliche Durchsetzung bleibt beim Kernel (wenn die Capability fehlt,
schlaegt der zugrundeliegende `socket()`-Syscall weiterhin fehl, ganz
unabhaengig von dieser Variable).

## Dashboard: Docker-Status und Systeminfo

**Warum ein weiterer isolierter Container statt direktem Socket-Mount.**
`/var/run/docker.sock` in `toolbox-backend` zu mounten waere der einfachste
Weg gewesen, ist aber effektiv root-Zugriff auf den gesamten Host --
Standard-Wissen in der Docker-Sicherheits-Community, siehe z.B. die
Tecnativa-Docker-Socket-Proxy-Dokumentation. Stattdessen: ein dedizierter
`docker-socket-proxy`-Container (bewaehrtes, weit verbreitetes Image), der
den echten Socket read-only mountet und global `POST=0` setzt -- damit sind
saemtliche schreibenden Docker-API-Aufrufe (Container starten/stoppen/
loeschen, Exec, Image-Pull, ...) blockiert, unabhaengig davon, was
`toolbox-backend` anfragt. Nur `CONTAINERS` (Liste/Status) und `INFO` sind
freigeschaltet.

**Warum die System-/Docker-Endpoints admin-only sind.** Beide geben
Einblick, der ueber die Toolbox selbst hinausgeht: CPU/RAM sind Host-Werte,
und die Docker-Container-Liste zeigt ALLE Container auf dem Host (Nextcloud,
BookStack, Vaultwarden, etc.), nicht nur toolbox-eigene. Das ist Betriebs-
Information, keine Toolbox-Funktionalitaet, und entsprechend nur fuer die
Rolle `admin` sichtbar.

## Abgelehnte Integration: Exploitarium

Ein vom Nutzer vorgeschlagenes GitHub-Repo (`exploitarium`) wurde geprueft
und NICHT integriert -- es enthaelt funktionierenden Exploit-Proof-of-
Concept-Code (RCE/LPE) fuer diverse reale Software. Funktionierender
Exploit-Code wird unabhaengig vom Verwendungszweck nicht eingebaut. Die
legitime Alternative fuer "bekannte Schwachstellen" bleibt der passive
Banner-Indikator (`vulnerability-indicators`).

## Alembic-Migrationen (Ablösung der Leichtgewicht-Loesung)

**Baseline-Migration statt historischer Einzelschritte.** Die erste
Alembic-Revision (`ca00304c2cd0_initial_schema.py`) wurde per Autogenerate
gegen eine leere Datenbank erzeugt und bildet exakt den JETZIGEN
Modellstand ab (inklusive aller Spalten, die vorher per Ad-hoc-ALTER-TABLE
nachgezogen wurden). Kuenftige Schema-Aenderungen werden ab jetzt als echte
Alembic-Revisionen erstellt (`alembic revision --autogenerate -m "..."`),
nicht mehr als Eintraege in `app/core/migrations.py`.

**Warum ein eigener Migrations-Runner statt direkt `alembic upgrade head`
im CMD.** Bestehende Installationen haben ihr Schema bisher nie ueber
Alembic bekommen (sondern ueber `create_all` + die Ad-hoc-Migration) --
wuerde man einfach `alembic upgrade head` aufrufen, wuerde die
Baseline-Migration versuchen, bereits existierende Tabellen neu
anzulegen und mit einem Fehler abbrechen. `app/scripts/run_migrations.py`
loest das:

1. Prueft, ob die Datenbank bereits eine `users`-Tabelle hat (= bestehende
   Installation) -- BEVOR irgendetwas veraendert wird.
2. Bei bestehender Installation: laesst zur Sicherheit einmal die alte
   Ad-hoc-Migration durchlaufen (bringt das Schema garantiert auf den
   Stand der Baseline, egal an welchem Zwischenstand die Installation
   gerade war), dann `alembic stamp head` (markiert die Baseline als
   "bereits angewendet", ohne sie auszufuehren).
3. Bei einer frischen Installation: direkt `alembic upgrade head`, das
   die Tabellen selbst anlegt -- hier laeuft bewusst KEIN `create_all`
   vorher, sonst wuerde Alembics eigenes `CREATE TABLE` kollidieren.

Dieser Runner wird im Dockerfile-CMD vor `uvicorn` ausgefuehrt, nicht mehr
im FastAPI-Startup-Event -- Schema-Migrationen sollen abgeschlossen sein,
bevor der Anwendungsprozess ueberhaupt startet.
