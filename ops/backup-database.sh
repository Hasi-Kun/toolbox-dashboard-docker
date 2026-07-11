#!/usr/bin/env bash
#
# Taegliches Backup der Toolbox-SQLite-Datenbank.
#
# Nutzt SQLite's eingebautes ".backup"-Kommando statt die Datei einfach
# zu kopieren -- ".backup" erstellt eine KONSISTENTE Kopie, auch waehrend
# die Datenbank gerade von der laufenden Anwendung beschrieben wird
# (rohes Kopieren koennte eine Datei mitten in einem Schreibvorgang
# erwischen und damit eine korrupte Sicherung erzeugen).
#
# Einrichtung (einmalig, auf dem Host, NICHT im Container):
#   1. Dieses Skript nach /data/toolbox/ops/backup-database.sh legen
#      (liegt nach dem Entpacken des Deployment-Pakets bereits dort).
#   2. chmod +x /data/toolbox/ops/backup-database.sh
#   3. Crontab-Eintrag fuer taegliches Backup um 03:00 Uhr:
#        0 3 * * * /data/toolbox/ops/backup-database.sh >> /var/log/toolbox-backup.log 2>&1
#      (mit `crontab -e` als root oder als der Nutzer, der Docker-Rechte hat)
#
# Backups landen in /data/toolbox-backups/ (ausserhalb des Docker-Volumes,
# damit ein Volume-Problem nicht gleichzeitig auch die Backups mitreisst).

set -euo pipefail

BACKUP_DIR="/data/toolbox-backups"
CONTAINER_NAME="toolbox-backend"
DB_PATH_IN_CONTAINER="/data/toolbox.db"
RETENTION_DAYS=14
TIMESTAMP="$(date +%Y-%m-%d_%H-%M-%S)"
BACKUP_FILE="${BACKUP_DIR}/toolbox-${TIMESTAMP}.db"

mkdir -p "${BACKUP_DIR}"

echo "[$(date)] Starte Backup..."

# ".backup" ueber sqlite3 INNERHALB des Containers ausfuehren (dort ist
# sqlite3 als Python-Abhaengigkeit bereits vorhanden), Ergebnis dann per
# docker cp aus dem Container herausholen.
docker compose exec -T "${CONTAINER_NAME}" python3 -c "
import sqlite3
src = sqlite3.connect('${DB_PATH_IN_CONTAINER}')
dst = sqlite3.connect('/tmp/backup-temp.db')
src.backup(dst)
src.close()
dst.close()
"
docker compose cp "${CONTAINER_NAME}:/tmp/backup-temp.db" "${BACKUP_FILE}"
docker compose exec -T "${CONTAINER_NAME}" rm -f /tmp/backup-temp.db

gzip "${BACKUP_FILE}"
echo "[$(date)] Backup gespeichert: ${BACKUP_FILE}.gz"

# Alte Backups jenseits der Aufbewahrungsfrist loeschen.
find "${BACKUP_DIR}" -name "toolbox-*.db.gz" -mtime "+${RETENTION_DAYS}" -delete

echo "[$(date)] Backup abgeschlossen. Vorhandene Backups:"
ls -lh "${BACKUP_DIR}"/toolbox-*.db.gz 2>/dev/null | tail -5
