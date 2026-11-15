#!/usr/bin/env bash
#
# Postgres backup for a Bridge deployment.
#
# WHY THIS EXISTS. `pgdata` holds every tenant, user, machine, session record and the whole
# management audit chain, and until this script nothing backed any of it up. The audit chain makes
# that sharper than ordinary data loss: its entire value is that it cannot be lost or altered, so an
# unbacked-up tamper-evident log is close to a contradiction.
#
# Run by deploy/bridge-backup.timer (daily), or by hand at any time. Safe to run while the stack is
# live: pg_dump takes a consistent snapshot in a single transaction and does not lock writers.
#
# RESTORE IS DOCUMENTED IN docs/22-backup-and-restore.md AND MUST BE TESTED. An untested backup is a
# belief, not a backup — and the moment you need it is the worst moment to discover the belief was
# wrong.

set -euo pipefail

# --- configuration -------------------------------------------------------------------------------
# Overridable from the environment or systemd unit; the defaults match docs/20's layout.
# Default: the install this script ships in (<install>/deploy/backup-db.sh); production's ~/rmt2 resolves to the
# same place. BRIDGE_REPO_DIR still overrides.
REPO_DIR="${BRIDGE_REPO_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
OUT_DIR="${BRIDGE_BACKUP_DIR:-$HOME/bridge-backups}"
KEEP="${BRIDGE_BACKUP_KEEP:-14}"

# ENCRYPTION AT REST (required). The dump is piped through `age` straight from pg_dump, so a plaintext
# copy never exists on disk and nothing needs securely deleting. Only PUBLIC keys live on this box:
# whoever steals the server or the off-box copy cannot read the backups, and the private key stays
# with the operator (docs/22 section 7). Configure ONE of:
#   BRIDGE_BACKUP_AGE_RECIPIENT=age1...                comma-separated list of age public keys
#   BRIDGE_BACKUP_AGE_RECIPIENTS_FILE=/path/to/file    one recipient per line (age -R format; also takes ssh public keys)
# With neither set the script REFUSES to run: it never falls back to a plaintext dump.
# (read after deploy/.env is sourced below, so the setting may live there too)

COMPOSE=(docker compose -f "$REPO_DIR/deploy/docker-compose.yml" -f "$REPO_DIR/deploy/docker-compose.prod.yml")

# --- preflight -----------------------------------------------------------------------------------
# Fail loudly and early. A backup job that half-works and exits 0 is worse than one that never ran,
# because it manufactures confidence.
[ -d "$REPO_DIR/deploy" ] || { echo "backup: no deploy/ under $REPO_DIR (set BRIDGE_REPO_DIR)" >&2; exit 1; }


# shellcheck disable=SC1091
set -a; . "$REPO_DIR/deploy/.env"; set +a
: "${POSTGRES_PASSWORD:?backup: POSTGRES_PASSWORD is not set in deploy/.env}"
DB="${POSTGRES_DB:-rmt}"
USER_NAME="${POSTGRES_USER:-rmt}"

AGE_RECIPIENT="${BRIDGE_BACKUP_AGE_RECIPIENT:-}"
AGE_RECIPIENTS_FILE="${BRIDGE_BACKUP_AGE_RECIPIENTS_FILE:-}"
AGE_ARGS=()
if [ -n "$AGE_RECIPIENTS_FILE" ]; then
  [ -s "$AGE_RECIPIENTS_FILE" ] || { echo "backup: BRIDGE_BACKUP_AGE_RECIPIENTS_FILE=$AGE_RECIPIENTS_FILE is missing or empty" >&2; exit 1; }
  AGE_ARGS+=(-R "$AGE_RECIPIENTS_FILE")
fi
if [ -n "$AGE_RECIPIENT" ]; then
  IFS=',' read -r -a _R <<< "$AGE_RECIPIENT"
  for r in "${_R[@]}"; do
    r="${r//[[:space:]]/}"
    [ -n "$r" ] || continue
    case "$r" in
      age1*) AGE_ARGS+=(-r "$r") ;;
      AGE-SECRET-KEY-*) echo "backup: that is an age PRIVATE key - never put it on the server; use the public key (age1...)" >&2; exit 1 ;;
      *) echo "backup: \"$r\" is not an age public key (age1...); ssh public keys go in BRIDGE_BACKUP_AGE_RECIPIENTS_FILE" >&2; exit 1 ;;
    esac
  done
fi
if [ "${#AGE_ARGS[@]}" -eq 0 ]; then
  echo "backup: REFUSING to write a plaintext backup. Set BRIDGE_BACKUP_AGE_RECIPIENT=age1... (your PUBLIC key; see docs/22-backup-and-restore.md section 7)" >&2
  exit 1
fi
command -v age >/dev/null || { echo "backup: 'age' is not installed (apt install age); refusing to write a plaintext backup" >&2; exit 1; }


mkdir -p "$OUT_DIR"
chmod 700 "$OUT_DIR"   # dumps contain password digests and the whole audit trail

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
TMP="$OUT_DIR/.bridge-$STAMP.sql.gz.age.partial"
OUT="$OUT_DIR/bridge-$DB-$STAMP.sql.gz.age"

# --- dump ----------------------------------------------------------------------------------------
# As the OWNER, not rmt_app. A dump must read every row of every tenant, and rmt_app is deliberately
# NOSUPERUSER with row-level security applied — dumping as it would produce a file that looks
# complete and silently contains only whatever tenant happened to be pinned.
#
# Written to a .partial first and renamed only on success, so an interrupted run (a reboot mid-dump,
# a full disk) can never leave a truncated file sitting in the directory looking like a backup.
# `</dev/null` below is NOT decoration. `docker compose exec -T` ATTACHES STDIN, so when this
# script is run with anything on stdin - piped in, fed by a heredoc, invoked from another script -
# the exec consumes the REST OF THE SCRIPT. The symptom is a run that stops mid-output with no
# error and exit 0, which is the worst possible failure mode for a backup. It cost the deployment
# session three truncated runs before they found it.
#
# systemd's default StandardInput=null already makes the timer path safe; this protects every OTHER
# way someone will eventually run it.
echo "backup: dumping $DB -> $OUT (age-encrypted; no plaintext is written)"
if ! "${COMPOSE[@]}" exec -T \
      postgres sh -c 'export PGPASSWORD="$POSTGRES_PASSWORD"; exec pg_dump -U "$1" -d "$2" --clean --if-exists' \
      backup "$USER_NAME" "$DB" </dev/null \
    | gzip -9 | age "${AGE_ARGS[@]}" > "$TMP"; then
  rm -f "$TMP"
  echo "backup: pg_dump FAILED — no file written" >&2
  exit 1
fi

# A dump that produced almost nothing is a failure the exit code did not report: pg_dump can emit a
# valid-but-empty script if it is pointed at the wrong database.
SIZE=$(stat -c %s "$TMP")
if [ "$SIZE" -lt 4096 ]; then
  rm -f "$TMP"
  echo "backup: dump was only ${SIZE}B — refusing to keep it; check the database name" >&2
  exit 1
fi

# The box holds no decryption key, so gzip -t is impossible here (the integrity check belongs to the
# restore drill, docs/22 section 5). What CAN be checked: the file is a real age stream (header), and
# every stage of the pipe succeeded (pipefail above - a failed gzip or age fails the whole run).
if [ "$(head -c 21 "$TMP")" != "age-encryption.org/v1" ]; then
  rm -f "$TMP"; echo "backup: output is not an age file - refusing to keep it" >&2; exit 1
fi

mv "$TMP" "$OUT"
chmod 600 "$OUT"
echo "backup: wrote $OUT ($(numfmt --to=iec "$SIZE" 2>/dev/null || echo "${SIZE}B"))"

# Legacy PLAINTEXT dumps from before encryption was required: never pruned or touched here (they are
# not covered by the encrypted-name retention below). Say so loudly every run until the operator has
# encrypted or securely deleted them (docs/22 section 7).
# nullglob arrays, not `ls | wc`: with no match `ls` exits non-zero and pipefail+errexit would kill the
# script AFTER the backup but BEFORE retention (the normal state once no plaintext files remain).
shopt -s nullglob
export LC_ALL=C   # glob order = byte order = ISO-stamp order
LEGACY_FILES=("$OUT_DIR"/bridge-*.sql.gz)
LEGACY=${#LEGACY_FILES[@]}
[ "$LEGACY" -eq 0 ] || echo "backup: WARNING $LEGACY legacy PLAINTEXT dump(s) (bridge-*.sql.gz) remain in $OUT_DIR - encrypt or shred them" >&2

# --- retention -----------------------------------------------------------------------------------
# By COUNT, not by age. Age-based pruning deletes everything when the job has been failing for
# longer than the window — precisely when you most need the old copies.
#
# Sorted by NAME, not mtime. The filenames carry ISO-8601 UTC stamps so they sort lexically, and
# mtime is a property of the filesystem rather than of the backup: a `cp` without `-p`, a restore
# from another medium, or a `touch` reorders it, and this loop DELETES things. Sorting on the value
# encoded in the name means what gets pruned cannot be changed by moving files around.
ENC=("$OUT_DIR"/bridge-*.sql.gz.age)
if [ "$KEEP" -ge 1 ] && [ "${#ENC[@]}" -gt "$KEEP" ]; then
  for f in "${ENC[@]:0:${#ENC[@]}-KEEP}"; do
    echo "backup: pruning $(basename "$f")"
    rm -f "$f"
  done
fi

ENC=("$OUT_DIR"/bridge-*.sql.gz.age)
echo "backup: ${#ENC[@]} copies retained in $OUT_DIR"
