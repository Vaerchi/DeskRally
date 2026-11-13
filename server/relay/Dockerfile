# =============================================================================================
# BUILD-VERIFIED 2026-08-26 by CI (.github/workflows/ci.yml, job `docker`), which builds this image
# on every push. The image BUILDS; the running stack is still unverified — nothing has stood the
# services up together and driven a session through them. See docs/18-selfhost-deployment.md §6 for
# the staged bring-up that would close that.
# =============================================================================================
#
# Relay — dumb, E2E-blind byte forwarder. Raw TCP on :9000 and WebSocket on :9001 (path /relay).
# Build context = this directory (server/relay).

# ---- build stage ---------------------------------------------------------------------------
FROM golang:1.26.9-alpine3.24 AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" -o /out/relay .

# ---- runtime stage -------------------------------------------------------------------------
FROM alpine:3.20
# busybox netstat is used for the health check (the relay has no HTTP health endpoint).
RUN adduser -D -u 10001 app
USER app
COPY --from=build /out/relay /usr/local/bin/relay

EXPOSE 9000 9001
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD netstat -ltn | grep -q ':9000' || exit 1

ENTRYPOINT ["/usr/local/bin/relay"]
CMD ["-tcp", ":9000", "-ws", ":9001"]
