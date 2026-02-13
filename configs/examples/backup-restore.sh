#!/bin/bash
# backup-restore.sh
# Automated backup and restore for ClawdBot

set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-$HOME/openclaw-backups}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_NAME="openclaw-backup-$TIMESTAMP"

# Backup function
backup() {
    echo "Starting backup: $BACKUP_NAME"

    mkdir -p "$BACKUP_DIR/$BACKUP_NAME"

    # Backup configurations
    echo "[1/5] Backing up configurations..."
    cp -r ~/.openclaw/config "$BACKUP_DIR/$BACKUP_NAME/"

    # Backup skills
    echo "[2/5] Backing up skills..."
    cp -r ~/.openclaw/skills "$BACKUP_DIR/$BACKUP_NAME/"

    # Backup logs (last 7 days)
    echo "[3/5] Backing up recent logs..."
    find ~/.openclaw/logs -type f -mtime -7 -exec cp {} "$BACKUP_DIR/$BACKUP_NAME/logs/" \;

    # Export credentials metadata (not actual secrets)
    echo "[4/5] Exporting credential metadata..."
    security find-generic-password -s "ai.openclaw" -g 2>&1 | grep -v "password:" > "$BACKUP_DIR/$BACKUP_NAME/credential-metadata.txt" || true

    # Create manifest
    echo "[5/5] Creating backup manifest..."
    cat > "$BACKUP_DIR/$BACKUP_NAME/MANIFEST.txt" << EOF
Backup Created: $(date)
ClawdBot Version: $(docker inspect clawdbot-production --format='{{.Config.Image}}')
Hostname: $(hostname)
User: $(whoami)

Files:
$(find "$BACKUP_DIR/$BACKUP_NAME" -type f | wc -l) files
$(du -sh "$BACKUP_DIR/$BACKUP_NAME" | cut -f1) total size
EOF

    # Create archive
    tar -czf "$BACKUP_DIR/$BACKUP_NAME.tar.gz" -C "$BACKUP_DIR" "$BACKUP_NAME"
    rm -rf "$BACKUP_DIR/$BACKUP_NAME"

    echo "✓ Backup complete: $BACKUP_DIR/$BACKUP_NAME.tar.gz"
}

# Restore function
restore() {
    local backup_file="$1"

    if [ ! -f "$backup_file" ]; then
        echo "Error: Backup file not found: $backup_file"
        exit 1
    fi

    echo "Restoring from: $backup_file"

    # Extract backup
    local temp_dir=$(mktemp -d)
    tar -xzf "$backup_file" -C "$temp_dir"

    # Stop ClawdBot
    echo "[1/4] Stopping ClawdBot..."
    docker stop clawdbot-production || true

    # Restore configurations
    echo "[2/4] Restoring configurations..."
    cp -r "$temp_dir"/*/config/* ~/.openclaw/config/

    # Restore skills
    echo "[3/4] Restoring skills..."
    cp -r "$temp_dir"/*/skills/* ~/.openclaw/skills/

    # Restart ClawdBot
    echo "[4/4] Starting ClawdBot..."
    docker start clawdbot-production

    rm -rf "$temp_dir"

    echo "✓ Restore complete"
}

# List backups
list_backups() {
    echo "Available backups:"
    ls -lh "$BACKUP_DIR"/*.tar.gz 2>/dev/null || echo "No backups found"
}

# Main
case "${1:-}" in
    backup)
        backup
        ;;
    restore)
        restore "${2:-}"
        ;;
    list)
        list_backups
        ;;
    *)
        echo "Usage: $0 {backup|restore <file>|list}"
        exit 1
        ;;
esac
