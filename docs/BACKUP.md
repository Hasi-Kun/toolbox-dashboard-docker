# Datenbank-Backup

Die Toolbox nutzt SQLite in einem Docker-Volume (`toolbox-db-data`) --
ohne eigenes Backup geht der komplette Datenbestand (Nutzer, Feature-
Requests, Audit-Log, Scan-Historie) bei einem Datenverlust des Volumes
unwiederbringlich verloren.

## Einrichtung (einmalig)

```bash
chmod +x /data/toolbox/ops/backup-database.sh
crontab -e
```

Folgende Zeile einfuegen fuer ein taegliches Backup um 03:00 Uhr:

```
0 3 * * * /data/toolbox/ops/backup-database.sh >> /var/log/toolbox-backup.log 2>&1
```

## Was das Skript macht

- Nutzt SQLites eingebautes `.backup`-Kommando (ueber ein kleines Python-
  Snippet innerhalb des Containers) -- das erstellt eine KONSISTENTE
  Kopie, auch waehrend die Anwendung gerade schreibt. Ein rohes Kopieren
  der `.db`-Datei koennte eine Schreiboperation mitten drin erwischen
  und eine korrupte Sicherung erzeugen.
- Komprimiert das Backup (gzip).
- Speichert Backups unter `/data/toolbox-backups/` -- bewusst AUSSERHALB
  des Docker-Volumes, damit ein Problem mit dem Volume nicht gleichzeitig
  auch die Backups mitreisst.
- Loescht Backups aelter als 14 Tage automatisch (anpassbar ueber
  `RETENTION_DAYS` im Skript).

## Wiederherstellen

```bash
/data/toolbox/ops/restore-database.sh /data/toolbox-backups/toolbox-2026-01-15_03-00-00.db.gz
```

Das Skript fragt vor dem Ueberschreiben nochmal explizit nach
Bestaetigung, stoppt kurz den Backend-Container, tauscht die Datei aus
und startet ihn wieder.

## Empfehlung

Zusaetzlich zu den lokalen Backups auf demselben Server: die Backups
regelmaessig (z.B. per `rsync`/`rclone`) auf einen ZWEITEN Ort kopieren
(anderer Server, S3-kompatibler Speicher o.ae.) -- ein Backup, das auf
demselben Server wie das Original liegt, hilft bei einem
Festplattenausfall oder einer versehentlichen Loeschung, aber nicht bei
einem kompletten Serververlust.
