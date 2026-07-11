# Sicherheitshinweis: Next.js-Schwachstellen (gefunden per Scan, Juli 2026)

## Was gefunden wurde

Ein Scan der eigenen Instanz zeigte mehrere CVEs fuer die zuvor
eingesetzte Next.js-Version 14.2.15:

| CVE | CVSS | Betrifft uns? | Status |
|---|---|---|---|
| CVE-2025-29927 (Middleware-Auth-Bypass) | 9.1 | **Ja** -- unsere `middleware.ts` macht eine Session-Pruefung | **Behoben** (Upgrade + Caddy-Mitigation) |
| CVE-2026-44578 (SSRF via WebSocket-Upgrade) | 8.6 | Vermutlich ja (Versionsbereich schliesst 14.2.x ein) | Braucht Next.js 15.5.16+/16.2.5+ (siehe unten) |
| CVE-2026-44573 (i18n-Datenroute-Bypass) | 7.5 | Nur falls i18n + Middleware-Autorisierung genutzt wird (bei uns nicht der Fall, aber sicherheitshalber ernst nehmen) | Braucht Next.js 15.5.16+/16.2.5+ |
| CVE-2025-67779 / CVE-2025-55184 (React Server Components DoS) | 7.5 | **Vermutlich nicht** -- betrifft `react-server-dom-*`-Pakete bei React 19.x, wir nutzen React 18.3.1 | Kein Handlungsbedarf, im Auge behalten |

## Was bereits behoben wurde

1. **Next.js von 14.2.15 auf 14.2.35 angehoben** (der letzte Patch der
   14.x-Reihe vor deren End-of-Life) -- behebt CVE-2025-29927 und
   weitere waehrend der 14.x-Laufzeit zurueckportierte CVEs
   (z.B. CVE-2025-57822 SSRF, CVE-2025-55173 Image-Optimization).
2. **Caddy-Mitigation ergaenzt**: der interne `x-middleware-subrequest`-
   Header wird jetzt bei JEDER eingehenden Anfrage entfernt, bevor sie
   das Frontend erreicht -- zusaetzliche Verteidigungsebene, unabhaengig
   von der Next.js-Version (siehe CADDY.md).

## Was noch offen ist -- und warum das ein separates Projekt sein sollte

**Next.js 14.x ist seit dem 26. Oktober 2025 End-of-Life.** Der letzte
Patch (14.2.35) kam am 11. Dezember 2025 -- neue, seither entdeckte CVEs
(wie die 2026er-Eintraege aus dem Scan) werden fuer 14.x NICHT MEHR
zurueckportiert. Vollstaendiger Schutz gegen ALLE gemeldeten CVEs
erfordert ein Upgrade auf Next.js 15 (Maintenance-LTS bis Oktober 2026)
oder 16 (aktuelle Active-LTS-Version).

Das ist bewusst NICHT Teil dieses Hotfixes, weil ein Versions-Sprung
14.x -> 15.x/16.x echte Breaking Changes mitbringt:
- Geaenderte Fetch-Caching-Standardwerte
- Asynchrone Request-APIs (teilweise andere Handhabung in Server
  Components/Route Handlers)
- Moeglicher Umstieg auf React 19 (je nach Next.js-Version verpflichtend)
- Turbopack-Ueberlegungen (bei 16.x der Standard-Bundler)

Ein solcher Umstieg sollte als eigenes, sorgfaeltig getestetes Vorhaben
angegangen werden (Staging-Umgebung, vollstaendiger Funktionstest aller
Seiten -- insbesondere WebAuthn/Passkeys, WebCLI, Datei-Uploads), nicht
als eiliger Hotfix. Empfehlung: zuerst auf 15.x (kleinerer Sprung),
danach in einem zweiten Schritt auf 16.x.

## Empfehlung fuer den weiteren Umgang

- Diesen Hotfix (14.2.35 + Caddy-Mitigation) zeitnah deployen -- behebt
  die kritischste, real bei uns ausnutzbare Luecke.
- Die 15.x/16.x-Migration als eigenes Vorhaben einplanen, wenn Zeit fuer
  gruendliches Testen da ist.
- Bei zukuenftigen Scans: Next.js-Versionsstand im Auge behalten, da die
  14.x-Reihe keine neuen Sicherheitsupdates mehr bekommt.
