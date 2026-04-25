#!/bin/bash
# backup-rotation.sh — Daily backup and rotation helper
#
# Benign fixture: SSH backup script that contains the word "ignore" in comments
# and command flags, but contains NO dangerous skill patterns (no eval/innerHTML/
# exec/child_process, no external URL).
# Used by: tests/security/test_evasion_hardening.py (Finding #10 — C5)

# ignore old compressed archives beyond 30-day retention
find /backups -name "*.tar.gz" -mtime +30 -delete

# sync data; ignore existing files at destination
rsync -avz --ignore-existing /data/ backup@192.168.1.10:/archive/

echo "Backup complete. Ignore any rsync permission warnings above."
