#!/bin/sh
# Literal KEY=value files: no shell evaluation, expansion, quote removal or command substitution.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SERVICE=${1:?usage: run-service.sh controlplane|signaling|relay|caddy [arguments]}
shift
case "$SERVICE" in controlplane|signaling|relay|caddy) ;; *) echo 'Unknown service' >&2; exit 2 ;; esac
CONFIG="$ROOT/config/$SERVICE.env"
[ -f "$CONFIG" ] || { echo "Create $CONFIG from its .env.example" >&2; exit 2; }
SEEN=' '
while IFS= read -r LINE || [ -n "$LINE" ]; do
    # Accept files edited on Windows, without including a CR in secrets.
    LINE=$(printf '%s' "$LINE" | tr -d '\r')
    case "$LINE" in ''|\#*) continue ;; esac
    case "$LINE" in *=*) ;; *) echo "Invalid config in $CONFIG" >&2; exit 2 ;; esac
    KEY=${LINE%%=*}
    case "$KEY" in ''|[!A-Z]*|*[!A-Z0-9_]*) echo "Invalid key in $CONFIG" >&2; exit 2 ;; esac
    case "$SEEN" in *" $KEY "*) echo "Duplicate key $KEY" >&2; exit 2 ;; esac
    SEEN="$SEEN$KEY "
    export "$KEY=${LINE#*=}"
done < "$CONFIG"
cd "$ROOT"
case "$SERVICE" in
    signaling) set -- -addr 127.0.0.1:8080 -relay 127.0.0.1:9000 "$@" ;;
    relay) set -- -tcp 127.0.0.1:9000 -ws 127.0.0.1:9001 "$@" ;;
    caddy) set -- run --config "$ROOT/Caddyfile" --adapter caddyfile "$@" ;;
esac
exec "$ROOT/bin/$SERVICE" "$@"
