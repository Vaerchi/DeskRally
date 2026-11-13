# =============================================================================================
# BUILD-VERIFIED 2026-08-26 by CI (.github/workflows/ci.yml, job `docker`), which builds this image
# on every push. The image BUILDS; the running stack is still unverified — nothing has stood the
# services up together and driven a session through them. See docs/18-selfhost-deployment.md §6 for
# the staged bring-up that would close that.
# =============================================================================================
#
# Control-plane — multi-tenant management API (auth, RBAC, grant minting, audit ingestion).
# Listens on :8081 (health /healthz, GET /grant/pubkey, POST /grant/mint, POST /audit/ingest, ...).
# Needs Postgres (DATABASE_URL) with control-plane/migrations/*.sql applied; runs a stub-auth DEV
# mode when DATABASE_URL is unset. Build context = this directory (control-plane).

# ---- build stage ---------------------------------------------------------------------------
FROM golang:1.26.9-alpine3.24 AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
# The runnable entry point is ./cmd/controlplane (the package root is a library).
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" -o /out/controlplane ./cmd/controlplane
# docs/68: the opt-in download-report ingest ships in the SAME image (compose service `reach-ingest`, profile `reach`,
# entrypoint overridden). Building it here costs a second small binary and changes nothing while that service is off.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" -o /out/reachingest ./cmd/reachingest

# ---- runtime stage -------------------------------------------------------------------------
FROM alpine:3.20
RUN apk add --no-cache wget && adduser -D -u 10001 app
# docs/63 R4: the mount point of the central-recording volume (deploy/docker-compose.prod.yml's `recordings`
# named volume), created HERE and owned by the runtime uid. WHY IT BELONGS IN THE IMAGE: Docker creates a
# missing mount-point directory as root:root, and the process below is uid 10001, so a fresh volume would be
# unwritable and the control plane would refuse to start the day RECORDING_MASTER_KEY is set ("recording: open
# volume ...: permission denied"). An EMPTY named volume is populated from the image's directory on first use
# (copy-up), ownership and mode included, so owning the directory here is what makes `up` work with no manual
# chown. Only the leaf is app-owned: /var/lib/deskrally stays root's. 0700 is what OpenRecordingStorage itself
# creates. Inert while storage is off: the directory is empty and nothing opens it. (A volume that already
# holds data is NOT re-chowned by Docker; see docs/20 "Turning on central recording storage".)
RUN mkdir -p /var/lib/deskrally/recordings \
 && chown app:app /var/lib/deskrally/recordings \
 && chmod 0700 /var/lib/deskrally/recordings
USER app
COPY --from=build /out/controlplane /usr/local/bin/controlplane
COPY --from=build /out/reachingest /usr/local/bin/reachingest
# Ship the migrations alongside the binary for reference / manual application.
COPY --from=build /src/migrations /opt/rmt/migrations

EXPOSE 8081
ENV CP_LISTEN=:8081
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8081/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/controlplane"]
