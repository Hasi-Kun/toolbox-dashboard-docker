#!/usr/bin/env bash
#
# Stellt ein Backup der Toolbox-Datenbank wieder her.
#
# Verwendung:
#   ./restore-database.sh /data/toolbox-backups/toolbox-2026-01-15_03-00-00.db.gz
#
# ACHTUNG: Ueberschreibt die AKTUELLE Datenbank. Der Backend-Container
# wird dafuer kurz gestoppt (waehrend die Datei ausgetauscht wird) und
# danach wieder gestartet.

set -euo pipefail

if [ $# -ne 1 ]; then
    echo "Verwendung: $0 <pfad-zum-backup.db.gz>"
    exit 1
fi

BACKUP_FILE="$1"
CONTAINER_NAME="toolbox-backend"

if [ ! -f "${BACKUP_FILE}" ]; then
    echo "Fehler: Backup-Datei nicht gefunden: ${BACKUP_FILE}"
    exit 1
fi

echo "ACHTUNG: Dies ueberschreibt die aktuelle Datenbank mit dem Inhalt von:"
echo "  ${BACKUP_FILE}"
read -rp "Wirklich fortfahren? (ja/nein): " CONFIRM
if [ "${CONFIRM}" != "ja" ]; then
    echo "Abgebrochen."
    exit 0
fi

TEMP_DB="/tmp/restore-temp.db"
gunzip -c "${BACKUP_FILE}" > "${TEMP_DB}"

echo "Stoppe ${CONTAINER_NAME}..."
docker compose stop "${CONTAINER_NAME}"

docker compose cp "${TEMP_DB}" "${CONTAINER_NAME}:/data/toolbox.db"
rm -f "${TEMP_DB}"

echo "Starte ${CONTAINER_NAME} wieder..."
docker compose start "${CONTAINER_NAME}"

echo "Fertig. Bitte in den Logs pruefen, dass der Start sauber verlief:"
echo "  docker compose logs -f ${CONTAINER_NAME}"
