#!/usr/bin/env bash
# pg_dump -> restic -> Backblaze B2 (via B2's S3-compatible API — restic's
# native B2 backend has weaker error handling than its S3 backend, so this
# deliberately targets the S3 endpoint, not b2:).
#
# Run by solarplex-backup.service (deploy/systemd/solarplex-backup.service),
# on a timer (deploy/systemd/solarplex-backup.timer). Credentials are
# delivered the same way solarplex.service's are — a second, independent
# age-encrypted file (backup-secrets.age, see
# deploy/ansible/roles/solarplex_backup/) decrypted at service start to a
# tmpfs EnvironmentFile via `secrets-cli decrypt-bytes`.
#
# Required env:
#   DATABASE_URL              same value the server itself uses
#   RESTIC_REPOSITORY         path-style S3 URL, e.g.
#                              s3:s3.us-west-004.backblazeb2.com/solarplex-backups
#                              (NOT the bucket.s3.*.backblazeb2.com virtual-host
#                              form — restic requires path-style)
#   RESTIC_PASSWORD           restic repository encryption passphrase
#   AWS_ACCESS_KEY_ID         B2 "S3 compatible" application key ID
#   AWS_SECRET_ACCESS_KEY     B2 "S3 compatible" application key
#
# Optional env:
#   BACKUP_KEEP_DAILY/WEEKLY/MONTHLY   retention counts, see defaults below
#   ALERT_WEBHOOK_URL                  same webhook solarplex-alert-watch.sh
#                                       posts to; if set, a failure here
#                                       posts a one-line alert too
#
# Requires: pg_dump, restic.
#
# Restore (manual, run on whatever host has the same RESTIC_REPOSITORY/
# RESTIC_PASSWORD/AWS_* env set — not part of this script, deliberately:
# a restore is a rare, high-stakes, human-supervised action, not something
# that should share a code path with the routine unattended backup job):
#   restic snapshots --tag solarplex-postgres          # find the snapshot
#   restic dump <snapshot-id> "solarplex-<stamp>.dump" > restore.dump
#   pg_restore -d "$DATABASE_URL" --clean --if-exists restore.dump
# `--clean --if-exists` drops conflicting objects before recreating them —
# only appropriate against a target database you intend to fully overwrite.

set -euo pipefail

: "${DATABASE_URL:?DATABASE_URL must be set}"
: "${RESTIC_REPOSITORY:?RESTIC_REPOSITORY must be set}"
: "${RESTIC_PASSWORD:?RESTIC_PASSWORD must be set}"
: "${AWS_ACCESS_KEY_ID:?AWS_ACCESS_KEY_ID must be set}"
: "${AWS_SECRET_ACCESS_KEY:?AWS_SECRET_ACCESS_KEY must be set}"

KEEP_DAILY="${BACKUP_KEEP_DAILY:-7}"
KEEP_WEEKLY="${BACKUP_KEEP_WEEKLY:-4}"
KEEP_MONTHLY="${BACKUP_KEEP_MONTHLY:-6}"
TAG="solarplex-postgres"

alert() {
	if [ -n "${ALERT_WEBHOOK_URL:-}" ]; then
		body=$(printf '{"text":"[solarplex-backup] %s"}' "$1")
		curl -fsS -X POST -H 'Content-Type: application/json' -d "$body" "$ALERT_WEBHOOK_URL" >/dev/null || true
	fi
}

on_err() {
	local exit_code=$?
	echo "backup-postgres: FAILED (exit $exit_code)" >&2
	alert "backup FAILED (exit $exit_code) — see journalctl -u solarplex-backup.service"
	exit "$exit_code"
}
trap on_err ERR

# Idempotent: restic errors on `snapshots` against an uninitialized repo,
# succeeds once `init` has run once. Safe to attempt on every run rather
# than requiring a separate manual bootstrap step.
if ! restic snapshots --tag "$TAG" >/dev/null 2>&1; then
	echo "backup-postgres: repository not yet initialized, running restic init"
	restic init
fi

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
echo "backup-postgres: dumping database and streaming to restic ($stamp)"

# -Fc (custom format): compressed, and restorable with pg_restore
# selectively (single table/schema) rather than only as an all-or-nothing
# SQL replay. --stdin avoids ever writing the dump to local disk.
pg_dump "$DATABASE_URL" -Fc |
	restic backup --stdin --stdin-filename "solarplex-${stamp}.dump" --tag "$TAG"

echo "backup-postgres: pruning old snapshots (keep daily=$KEEP_DAILY weekly=$KEEP_WEEKLY monthly=$KEEP_MONTHLY)"
restic forget --tag "$TAG" \
	--keep-daily "$KEEP_DAILY" \
	--keep-weekly "$KEEP_WEEKLY" \
	--keep-monthly "$KEEP_MONTHLY" \
	--prune

echo "backup-postgres: done"
