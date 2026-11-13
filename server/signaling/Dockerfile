# =============================================================================================
# BUILD-VERIFIED 2026-08-26 by CI (.github/workflows/ci.yml, job `docker`), which builds this image
# on every push. The image BUILDS; the running stack is still unverified — nothing has stood the
# services up together and driven a session through them. See docs/18-selfhost-deployment.md §6 for
# the staged bring-up that would close that.
# =============================================================================================
#
# Signaling server — WebSocket rendezvous (registration, brokering, SDP/candidate relay).
# Listens on :8080 (ws /ws, health /healthz). Build context = this directory (server/signaling).

# ---- build stage ---------------------------------------------------------------------------
FROM golang:1.26.9-alpine3.24 AS build
WORKDIR /src

# Cache module downloads before copying the rest of the source.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# Static, stripped binary — CGO off so it runs on a scratch/distroless base.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" -o /out/signaling .

# ---- runtime stage -------------------------------------------------------------------------
FROM alpine:3.20
RUN apk add --no-cache wget && adduser -D -u 10001 app
USER app
COPY --from=build /out/signaling /usr/local/bin/signaling

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/signaling"]
CMD ["-addr", ":8080"]
