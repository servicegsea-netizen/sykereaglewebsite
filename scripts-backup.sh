#!/bin/sh
set -eu
: "${BACKUP_DIR:=./backups}"
: "${DATA_DIR:=./data}"
: "${UPLOAD_DIR:=./uploads}"
mkdir -p "$BACKUP_DIR"
timestamp=$(date -u +%Y%m%dT%H%M%SZ)
tar -czf "$BACKUP_DIR/gsea-$timestamp.tar.gz" "$DATA_DIR" "$UPLOAD_DIR"
echo "Backup created: $BACKUP_DIR/gsea-$timestamp.tar.gz"
