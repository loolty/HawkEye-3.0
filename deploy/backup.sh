#!/usr/bin/env bash
# Nightly database backup (Linux). Reads the MYSQL_* values from ../.env.
#   chmod +x deploy/backup.sh
#   crontab -e  ->  30 2 * * *  /opt/hawkeye/deploy/backup.sh >> /opt/hawkeye/logs/backup.log 2>&1
# Copy the files in backups/ OFF this server too (another machine or cloud storage).
set -euo pipefail
APP_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BACKUP_DIR="${BACKUP_DIR:-$APP_DIR/backups}"
KEEP_DAYS="${KEEP_DAYS:-14}"

get() { grep -E "^$1=" "$APP_DIR/.env" | tail -1 | cut -d= -f2- | sed -e 's/^["'\'']//' -e 's/["'\'']$//' || true; }
DB_HOST="$(get MYSQL_HOST)"; DB_PORT="$(get MYSQL_PORT)"; DB_NAME="$(get MYSQL_DATABASE)"
DB_USER="$(get MYSQL_USER)"; DB_PASS="$(get MYSQL_PASSWORD)"
: "${DB_NAME:?MYSQL_DATABASE not found in .env}"

umask 077                                   # backups contain patient data: owner-only
mkdir -p "$BACKUP_DIR"
OUT="$BACKUP_DIR/${DB_NAME}_$(date +%Y%m%d-%H%M%S).sql.gz"
TMP="$OUT.partial"
trap 'rm -f "$TMP"' EXIT                    # a failed run must never leave a file that looks like a backup
MYSQL_PWD="$DB_PASS" mysqldump --host="${DB_HOST:-127.0.0.1}" --port="${DB_PORT:-3306}" --user="$DB_USER" \
    --single-transaction --routines --default-character-set=utf8mb4 "$DB_NAME" | gzip > "$TMP"
gzip -t "$TMP"                              # verify the archive is readable
[ "$(gzip -dc "$TMP" | head -c 200 | wc -c)" -gt 100 ] || { echo "backup is suspiciously empty" >&2; exit 1; }
mv "$TMP" "$OUT"
find "$BACKUP_DIR" -name '*.sql.gz' -mtime +"$KEEP_DAYS" -delete
echo "$(date '+%F %T') backup OK: $OUT ($(du -h "$OUT" | cut -f1))"
