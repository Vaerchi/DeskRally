#!/usr/bin/env bash
#
# Keep the NON-ROOT coturn's certificate current (audit #19). Run it (a) ONCE before first starting
# the non-root coturn, then (b) daily by deploy/turn-cert-sync.timer. Idempotent.
#
# What it does:
#   1. Builds (cached) and runs the one-shot `turn-cert-export` service: it stages Caddy's TURN cert
#      + key, validates the pair (parses, hostname, not expired, key matches), and publishes it as a
#      new generation by an atomic symlink flip. Nothing invalid is ever published.
#   2. If a new generation was published it records a PENDING-ACTIVATION marker BEFORE touching
#      coturn. The marker is cleared only after coturn restarted AND a real TLS handshake to the
#      TURNS port served the exported certificate (fingerprint compared). If the restart or the
#      probe fails, or this script is interrupted, the next run sees the marker and retries even
#      though the export says UNCHANGED.
#   3. Whenever coturn exists, probes it every run (so a dead/stale TURNS listener fails the timer
#      visibly instead of rotting). A served certificate that differs from the exported one also
#      triggers activation.
#
# Exit status: 0 = coturn serves the exported certificate (or is not created yet); non-zero otherwise.
# See docs/20-ubuntu-host-runbook.md section 9, "Hardening: non-root coturn".

set -euo pipefail

# Default: the install this script ships in (<install>/deploy/turn-cert-sync.sh), so a fresh install works as the
# guides show it. Production's ~/rmt2 resolves to the same place; BRIDGE_REPO_DIR still overrides.
REPO_DIR="${BRIDGE_REPO_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
ENV_FILE="${BRIDGE_ENV_FILE:-$REPO_DIR/deploy/.env}"
STATE_DIR="${BRIDGE_STATE_DIR:-$HOME/.local/state/deskrally}"
MARK="$STATE_DIR/turn-cert-pending"
[ -f "$ENV_FILE" ] || { echo "turn-cert-sync: no $ENV_FILE (set BRIDGE_REPO_DIR / BRIDGE_ENV_FILE)" >&2; exit 1; }
command -v openssl >/dev/null || { echo "turn-cert-sync: openssl is required on the host for the TLS probe" >&2; exit 1; }
mkdir -p "$STATE_DIR"

# shellcheck disable=SC1090
set -a; . "$ENV_FILE"; set +a
H="${TURN_SITE_ADDRESS:-turn.deskrally.com}"
# coturn listens on TURN_RELAY_IP (--listening-ip), on the INTERNAL TLS port; override for another target
# (e.g. TURN_PROBE_ADDR=203.0.113.10:443 to test through the gateway forward).
ADDR="${TURN_PROBE_ADDR:-${TURN_RELAY_IP:?turn-cert-sync: TURN_RELAY_IP is not set in $ENV_FILE}:${TURN_TLS_PORT:-5349}}"

# Same file set the operator uses to run coturn (docs/20 section 9). Add -f docker-compose.release.yml
# via BRIDGE_COMPOSE_EXTRA if the deployment layers it.
COMPOSE=(docker compose --env-file "$ENV_FILE"
         -f "$REPO_DIR/deploy/docker-compose.yml"
         -f "$REPO_DIR/deploy/docker-compose.prod.yml"
         -f "$REPO_DIR/deploy/docker-compose.turn.yml")
# shellcheck disable=SC2206
[ -n "${BRIDGE_COMPOSE_EXTRA:-}" ] && COMPOSE+=($BRIDGE_COMPOSE_EXTRA)

# `</dev/null` on every compose call: `-T`/exec would otherwise attach stdin and eat the rest of a
# piped script (the trap backup-db.sh documents).
"${COMPOSE[@]}" build --quiet turn-cert-export </dev/null >/dev/null \
  || { echo "turn-cert-sync: building the exporter image FAILED (needs network once)" >&2; exit 1; }
OUT="$("${COMPOSE[@]}" run --rm -T turn-cert-export </dev/null)" \
  || { echo "turn-cert-sync: the cert export FAILED (nothing was published)" >&2; exit 1; }
echo "$OUT"

LINE="$(printf '%s\n' "$OUT" | grep -E '^turn-cert-export: (CHANGED|UNCHANGED) ' | tail -n 1 || true)"
[ -n "$LINE" ] || { echo "turn-cert-sync: unexpected export output (no CHANGED/UNCHANGED line)" >&2; exit 1; }
STATE="$(awk '{print $2}' <<<"$LINE")"
GEN="$(sed -n 's/.* gen=\([^ ]*\).*/\1/p' <<<"$LINE")"
SUM="$(sed -n 's/.* sha256=\([0-9a-f]*\).*/\1/p' <<<"$LINE")"
[ -n "$GEN" ] && [ -n "$SUM" ] || { echo "turn-cert-sync: cannot parse generation/fingerprint from: $LINE" >&2; exit 1; }

# Record the pending activation BEFORE touching coturn; cleared only after a verified handshake.
if [ "$STATE" = CHANGED ]; then
  printf '%s %s\n' "$GEN" "$SUM" > "$MARK"
fi

# probe TRIES: a real TLS handshake with SNI; success only if the SERVED certificate's SHA-256 equals
# the exported one (a handshake that merely succeeds with an old cert is exactly the failure to catch).
probe() {
  local tries="$1" i got
  for ((i = 1; i <= tries; i++)); do
    got="$(echo | timeout 10 openssl s_client -connect "$ADDR" -servername "$H" 2>/dev/null \
           | openssl x509 -noout -fingerprint -sha256 -subject -enddate 2>/dev/null || true)"
    if [ -n "$got" ] && [ "$(sed -n 's/.*Fingerprint=//p' <<<"$got" | tr -d ':' | tr 'A-F' 'a-f')" = "$SUM" ]; then
      echo "turn-cert-sync: TURNS $ADDR served the exported certificate ($(tr '\n' ' ' <<<"$got" | sed 's/sha256 Fingerprint=[^ ]* //'))"
      return 0
    fi
    [ "$i" -eq "$tries" ] || sleep "${PROBE_SLEEP:-2}"
  done
  return 1
}

if [ -z "$("${COMPOSE[@]}" ps -aq coturn </dev/null)" ]; then
  [ ! -f "$MARK" ] || { echo "turn-cert-sync: coturn is not created yet; it will start on generation $GEN"; rm -f "$MARK"; }
  exit 0
fi

# No marker but TURNS serves something else (or nothing): activation is needed all the same.
if [ ! -f "$MARK" ] && ! probe 1; then
  echo "turn-cert-sync: TURNS is not serving the exported certificate - activating"
  printf '%s %s\n' "$GEN" "$SUM" > "$MARK"
fi

if [ -f "$MARK" ]; then
  echo "turn-cert-sync: activating generation $GEN (restarting coturn)"
  "${COMPOSE[@]}" restart coturn </dev/null \
    || { echo "turn-cert-sync: coturn restart FAILED - activation stays pending, the next run retries" >&2; exit 1; }
fi

if probe "${PROBE_TRIES:-10}"; then
  rm -f "$MARK"
else
  echo "turn-cert-sync: TURNS at $ADDR is NOT serving the exported certificate (check 'docker logs' for coturn; common causes: port below the host's unprivileged threshold, wrong TURN_RELAY_IP). Activation stays pending." >&2
  exit 1
fi
