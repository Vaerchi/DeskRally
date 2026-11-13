#!/usr/bin/env bash
# Build a DeskRally SERVER RELEASE PACKAGE: everything a new host needs, with no build tools there.
#
#   scripts/package-server-release.sh 0.1.4            # run on Linux with Docker and Node 20+
#
# Output (in dist/server-release/):
#   deskrally-server-<v>.tar.gz             the package
#   deskrally-server-<v>.tar.gz.sha256.txt  its SHA-256 ("<hash>  <file>")
#   latest.json                             {"version","file","sha256","commit"}
# Publish all three under /download/server/ (deploy/Caddyfile allows exactly these names).
#
# The package contains the prebuilt control-plane / signaling / relay images (docker save), the
# built web console, the deploy/ files (git-tracked only, so no .env), install.sh, INSTALL.md and
# the silent-install provisioning script under dist/artifacts/agent/.
set -euo pipefail

VERSION=${1:?usage: package-server-release.sh <version, e.g. 0.1.4>}
[[ $VERSION =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || { echo "version must be X.Y.Z" >&2; exit 2; }
ROOT=$(git rev-parse --show-toplevel)
cd "$ROOT"
[ -z "$(git status --porcelain)" ] || { echo "working tree not clean; package a committed state" >&2; exit 1; }
COMMIT=$(git rev-parse HEAD)
OUT=${OUT_DIR:-$ROOT/dist/server-release}
NAME=deskrally-server-$VERSION
STAGE=$OUT/$NAME
[ -e "$STAGE" ] && { echo "$STAGE exists; remove it first" >&2; exit 1; }
mkdir -p "$STAGE/images" "$STAGE/dist/viewer" "$STAGE/dist/artifacts/agent"

echo "==> images"
docker build -t "deskrally/controlplane:$VERSION" control-plane
docker build -t "deskrally/signaling:$VERSION" server/signaling
docker build -t "deskrally/relay:$VERSION" server/relay
docker save "deskrally/controlplane:$VERSION" "deskrally/signaling:$VERSION" "deskrally/relay:$VERSION" \
  | gzip -9 >"$STAGE/images/deskrally-images.tar.gz"

echo "==> web console"
# A clean build with NO VITE_* settings: same-origin /cp, and no support-tool download (that build
# has its server address compiled in, so it is published per deployment, not in this package).
# VITE_DEFAULT_ORIGIN=none: a generic package has no default host to name, so its join page is the neutral one
# (docs/66 2i); explicit so an exported value from the caller's shell cannot leak into the package.
(cd web/viewer && npm ci && env -u VITE_SUPPORT_DOWNLOAD_URL -u VITE_SUPPORT_DOWNLOAD_SHA256 -u VITE_PRODUCT_NAME -u VITE_SUPPORT_BUNDLE_ENABLED VITE_DEFAULT_ORIGIN=none npm run build)
cp -r web/viewer/dist/. "$STAGE/dist/viewer/"
cp "$STAGE/dist/viewer/index.html" "$STAGE/dist/viewer/join.html"

echo "==> deploy files, installer, docs"
git archive HEAD deploy | tar -x -C "$STAGE"
cp scripts/server-install.sh "$STAGE/install.sh" && chmod 755 "$STAGE/install.sh"
cp docs/guides/server-deployment.md "$STAGE/INSTALL.md"
cp docs/guides/client-deployment.md "$STAGE/CLIENTS.md"
cp scripts/new-msi-provisioning.ps1 "$STAGE/dist/artifacts/agent/"
(cd "$STAGE/dist/artifacts/agent" && sha256sum new-msi-provisioning.ps1 >new-msi-provisioning.ps1.sha256.txt)
printf '%s\n' "$VERSION" >"$STAGE/VERSION"
printf '%s\n' "$COMMIT" >"$STAGE/SOURCE_COMMIT"

echo "==> privacy check"
# The package is public. Refuse to ship a real email address or a deployment's public IP — a login
# email published here is enough to trigger that account's lockout, and the live config files this
# is built from once carried both. Example/documentation values are allowed.
emails=$(grep -rIhoE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' "$STAGE"   | grep -viE '@(example\.(com|org|net|test)|[a-z0-9.-]*\.(test|invalid|example|local))$'   | grep -viE '^(git@github\.com|noreply@anthropic\.com)$' | sort -u || true)
ips=$(grep -rIhoE '([0-9]{1,3}\.){3}[0-9]{1,3}' "$STAGE/deploy" "$STAGE"/*.md   | grep -vE '^(10\.|127\.|0\.|255\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|224\.|240\.|8\.8\.|1\.1\.1\.1)' | sort -u || true)
if [ -n "$emails$ips" ]; then
  echo "REFUSING to package: personal or deployment-specific values found:" >&2
  printf '  %s\n' $emails $ips >&2
  exit 1
fi

echo "==> archive"
tar -C "$OUT" -czf "$OUT/$NAME.tar.gz" "$NAME"
(cd "$OUT" && sha256sum "$NAME.tar.gz" >"$NAME.tar.gz.sha256.txt")
SHA=$(cut -d' ' -f1 "$OUT/$NAME.tar.gz.sha256.txt")
printf '{"version":"%s","file":"%s.tar.gz","sha256":"%s","commit":"%s"}\n' "$VERSION" "$NAME" "$SHA" "$COMMIT" >"$OUT/latest.json"
rm -rf "$STAGE"
ls -l "$OUT"
echo "done: $OUT/$NAME.tar.gz ($SHA)"
